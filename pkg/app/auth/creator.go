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
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID ids.GatewayID
	Name      string
	Type      domain.Type
	Enabled   bool
	Config    domain.Config
	// ExpiresAt retires an api key on its own. Nil is no expiry.
	ExpiresAt *time.Time
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=auth_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Auth, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo   domain.Repository
	events *KeyEvents
}

// NewCreator returns the Creator of admin-managed auths.
func NewCreator(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, signaler configsyncport.SnapshotSignaler) Creator {
	return &creator{repo: repo, events: NewKeyEvents(manager, publisher, logger, signaler)}
}

// KeyEvents tells the rest of the gateway that a new auth was stored: it warms
// this replica's caches with it, invalidates every other replica's and asks
// for a new config snapshot.
type KeyEvents struct {
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
}

// NewKeyEvents returns the KeyEvents of the auth caches in manager.
func NewKeyEvents(manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, signaler configsyncport.SnapshotSignaler) *KeyEvents {
	return &KeyEvents{
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
	}
}

// Saved announces a, which was just stored.
func (e *KeyEvents) Saved(ctx context.Context, a *domain.Auth) {
	e.memoryCache.Set(a.ID.String(), a)
	if a.KeyHash != "" {
		e.keyCache.Set(a.KeyHash, a)
	}
	invalidation.GatewayData(ctx, e.publisher, e.logger, a.GatewayID)
	if e.signaler != nil {
		e.signaler.Signal(ctx)
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Auth, error) {
	a, err := c.build(in)
	if err != nil {
		return nil, err
	}
	if err := ensureNoOAuth2Conflict(ctx, c.repo, a); err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, a); err != nil {
		return nil, err
	}
	c.events.Saved(ctx, a)
	return a, nil
}

func (c *creator) build(in CreateInput) (*domain.Auth, error) {
	if in.Type == domain.TypeAPIKey {
		return domain.NewAPIKeyAuth(in.GatewayID, in.Name, in.Enabled, in.ExpiresAt)
	}
	if in.ExpiresAt != nil {
		return nil, fmt.Errorf("%w: only api_key auths expire", domain.ErrInvalidType)
	}
	return domain.NewAuth(in.GatewayID, in.Name, in.Type, in.Enabled, in.Config)
}
