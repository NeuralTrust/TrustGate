// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

var ErrPersonalKeyHybrid = fmt.Errorf("auth: personal keys are unavailable on hybrid gateways: %w", commonerrors.ErrValidation)

type PersonalKey struct {
	Auth        *domain.Auth
	ConsumerIDs []ids.ConsumerID
}

//go:generate mockery --name=PersonalKeys --dir=. --output=./mocks --filename=auth_personal_keys_mock.go --case=underscore --with-expecter
type PersonalKeys interface {
	Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error)
	Create(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiresAt time.Time) (*PersonalKey, error)
	Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiresAt *time.Time) (*PersonalKey, error)
	Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error
}

var _ PersonalKeys = (*personalKeys)(nil)

type personalKeys struct {
	repo        domain.Repository
	consumers   consumerdomain.Reader
	gateways    gatewaydomain.Repository
	rotator     Rotator
	deleter     Deleter
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	now         func() time.Time
}

func NewPersonalKeys(
	repo domain.Repository,
	consumers consumerdomain.Reader,
	gateways gatewaydomain.Repository,
	rotator Rotator,
	deleter Deleter,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	now func() time.Time,
) PersonalKeys {
	return &personalKeys{
		repo:        repo,
		consumers:   consumers,
		gateways:    gateways,
		rotator:     rotator,
		deleter:     deleter,
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		now:         now,
	}
}

func (p *personalKeys) Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error) {
	a, err := p.find(ctx, gatewayID, ownerID)
	if err != nil {
		return nil, err
	}
	consumers, err := p.consumers.ListByAuthID(ctx, a.ID)
	if err != nil {
		return nil, fmt.Errorf("auth: list consumers of personal key: %w", err)
	}
	key := &PersonalKey{Auth: a, ConsumerIDs: make([]ids.ConsumerID, 0, len(consumers))}
	for _, c := range consumers {
		key.ConsumerIDs = append(key.ConsumerIDs, c.ID)
	}
	return key, nil
}

func (p *personalKeys) Create(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiresAt time.Time) (*PersonalKey, error) {
	a, err := domain.NewOwnedAPIKeyAuth(gatewayID, ownerID, expiresAt, p.now())
	if err != nil {
		return nil, err
	}
	if err := p.ensureNotHybrid(ctx, gatewayID); err != nil {
		return nil, err
	}
	switch _, err := p.repo.FindByOwner(ctx, gatewayID, ownerID); {
	case err == nil:
		return nil, domain.ErrOwnedKeyExists
	case !errors.Is(err, domain.ErrNotFound):
		return nil, fmt.Errorf("auth: find personal key: %w", err)
	}
	if err := p.repo.Save(ctx, a); err != nil {
		return nil, fmt.Errorf("auth: save personal key: %w", err)
	}
	p.memoryCache.Set(a.ID.String(), a)
	p.keyCache.Set(a.KeyHash, a)
	invalidation.GatewayData(ctx, p.publisher, p.logger, gatewayID)
	if p.signaler != nil {
		p.signaler.Signal(ctx)
	}
	return &PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}, nil
}

func (p *personalKeys) Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiresAt *time.Time) (*PersonalKey, error) {
	now := p.now()
	var expiry *ExpiryChange
	if expiresAt != nil {
		if err := domain.ValidateOwnedExpiry(*expiresAt, now); err != nil {
			return nil, err
		}
		expiry = &ExpiryChange{At: expiresAt}
	}
	current, err := p.Get(ctx, gatewayID, ownerID)
	if err != nil {
		return nil, err
	}
	if expiry == nil && current.Auth.IsExpired(now) {
		return nil, domain.ErrOwnedExpiry
	}
	rotated, err := p.rotator.Rotate(ctx, RotateInput{ID: current.Auth.ID, GatewayID: gatewayID, Expiry: expiry, OwnerID: ownerID})
	if err != nil {
		return nil, err
	}
	return &PersonalKey{Auth: rotated, ConsumerIDs: current.ConsumerIDs}, nil
}

func (p *personalKeys) Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error {
	existing, err := p.find(ctx, gatewayID, ownerID)
	if err != nil {
		return err
	}
	return p.deleter.Delete(ctx, gatewayID, existing.ID)
}

func (p *personalKeys) find(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*domain.Auth, error) {
	if err := domain.ValidateOwner(ownerID); err != nil {
		return nil, err
	}
	a, err := p.repo.FindByOwner(ctx, gatewayID, ownerID)
	if err != nil {
		return nil, fmt.Errorf("auth: find personal key: %w", err)
	}
	if err := a.ManagedBy(ownerID); err != nil {
		return nil, domain.ErrNotFound
	}
	return a, nil
}

func (p *personalKeys) ensureNotHybrid(ctx context.Context, gatewayID ids.GatewayID) error {
	gw, err := p.gateways.FindByID(ctx, gatewayID)
	if err != nil {
		return fmt.Errorf("auth: load gateway: %w", err)
	}
	if gw.ServedByHybridDataPlane() {
		return ErrPersonalKeyHybrid
	}
	return nil
}
