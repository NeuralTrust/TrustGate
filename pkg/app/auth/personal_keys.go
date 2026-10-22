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
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// PersonalKey is a user's personal key on a gateway and the personal
// consumers it is attached to.
type PersonalKey struct {
	Auth        *domain.Auth
	ConsumerIDs []ids.ConsumerID
}

// PersonalKeyOwner is the user a personal key is issued to: their platform
// user id, and the email every call the key makes is shown under. Email may be
// empty; it is then recorded later, when the console reconciles the key.
type PersonalKeyOwner struct {
	ID    string
	Email string
}

// PersonalKeys is the self-service lifecycle of the keys a user holds on a
// gateway, each scoped to the caller as owner. A user holds at most one
// personal key, which belongs to no group, and at most one key per directory
// group the console lets them hold one for. Get, Rotate and Revoke act on the
// personal key.
//
//go:generate mockery --name=PersonalKeys --dir=. --output=./mocks --filename=auth_personal_keys_mock.go --case=underscore --with-expecter
type PersonalKeys interface {
	Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error)
	// Create issues the owner their personal key when group is the zero
	// KeyGroup, else their key for group. A nil expiresAt never expires.
	Create(ctx context.Context, gatewayID ids.GatewayID, owner PersonalKeyOwner, group domain.KeyGroup, expiresAt *time.Time) (*PersonalKey, error)
	// Rotate replaces the secret. A nil expiry keeps the current expiry, which
	// an expired key cannot; a non-nil one sets it, or clears it when its At
	// is nil.
	Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiry *ExpiryChange) (*PersonalKey, error)
	Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error
}

var _ PersonalKeys = (*personalKeys)(nil)

type personalKeys struct {
	repo     domain.Repository
	links    consumerdomain.LinkReader
	gateways gatewaydomain.Repository
	rotator  Rotator
	deleter  Deleter
	events   *KeyEvents
	now      func() time.Time
}

// NewPersonalKeys returns the PersonalKeys use case. events announces a key it
// creates; rotation and revocation announce themselves.
func NewPersonalKeys(
	repo domain.Repository,
	links consumerdomain.LinkReader,
	gateways gatewaydomain.Repository,
	rotator Rotator,
	deleter Deleter,
	events *KeyEvents,
	now func() time.Time,
) PersonalKeys {
	return &personalKeys{
		repo:     repo,
		links:    links,
		gateways: gateways,
		rotator:  rotator,
		deleter:  deleter,
		events:   events,
		now:      utcClock(now),
	}
}

func (p *personalKeys) Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*PersonalKey, error) {
	a, err := p.find(ctx, gatewayID, ownerID)
	if err != nil {
		return nil, err
	}
	consumerIDs, err := p.links.ListIDsByAuthID(ctx, a.ID)
	if err != nil {
		return nil, fmt.Errorf("auth: list consumers of personal key: %w", err)
	}
	if consumerIDs == nil {
		consumerIDs = []ids.ConsumerID{}
	}
	return &PersonalKey{Auth: a, ConsumerIDs: consumerIDs}, nil
}

func (p *personalKeys) Create(ctx context.Context, gatewayID ids.GatewayID, owner PersonalKeyOwner, group domain.KeyGroup, expiresAt *time.Time) (*PersonalKey, error) {
	ownerID := owner.ID
	a, err := domain.NewOwnedAPIKeyAuth(gatewayID, ownerID, group, expiresAt, p.now())
	if err != nil {
		return nil, err
	}
	if err := a.SetOwnerEmail(owner.Email, a.CreatedAt); err != nil {
		return nil, err
	}
	if err := p.ensureNotHybrid(ctx, gatewayID); err != nil {
		return nil, err
	}
	// The unique index refuses a second key all the same; asking first gives
	// the common case its answer without a failed insert.
	switch _, err := p.repo.FindByOwnerAndGroup(ctx, gatewayID, ownerID, a.GroupID); {
	case err == nil:
		return nil, domain.ErrOwnedKeyExists
	case !errors.Is(err, domain.ErrNotFound):
		return nil, fmt.Errorf("auth: find personal key: %w", err)
	}
	if err := p.repo.Save(ctx, a); err != nil {
		return nil, fmt.Errorf("auth: save personal key: %w", err)
	}
	p.events.Saved(ctx, a)
	return &PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}, nil
}

func (p *personalKeys) Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string, expiry *ExpiryChange) (*PersonalKey, error) {
	if err := validateOwnedExpiryChange(expiry, p.now()); err != nil {
		return nil, err
	}
	current, err := p.Get(ctx, gatewayID, ownerID)
	if err != nil {
		return nil, err
	}
	return p.rotate(ctx, gatewayID, ownerID, current, expiry)
}

// rotate replaces the secret of current, one of ownerID's keys. A key that
// has expired is not brought back on its old expiry: the caller names a new
// one, or asks for none.
func (p *personalKeys) rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string, current *PersonalKey, expiry *ExpiryChange) (*PersonalKey, error) {
	if expiry == nil && current.Auth.IsExpired(p.now()) {
		return nil, fmt.Errorf("%w: the key has expired, so its rotation needs a new expiry", domain.ErrOwnedExpiry)
	}
	rotated, err := p.rotator.Rotate(ctx, RotateInput{ID: current.Auth.ID, GatewayID: gatewayID, Expiry: expiry, OwnerID: ownerID})
	if err != nil {
		return nil, err
	}
	return &PersonalKey{Auth: rotated, ConsumerIDs: current.ConsumerIDs}, nil
}

// validateOwnedExpiryChange refuses an expiry a personal key may not take.
// Keeping the current one, and never expiring, are always allowed.
func validateOwnedExpiryChange(expiry *ExpiryChange, now time.Time) error {
	if expiry == nil || expiry.At == nil {
		return nil
	}
	return domain.ValidateOwnedExpiry(*expiry.At, now)
}

func (p *personalKeys) Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error {
	existing, err := p.find(ctx, gatewayID, ownerID)
	if err != nil {
		return err
	}
	return p.deleter.Delete(ctx, gatewayID, existing.ID)
}

// find is the owner's personal key, the one held for no group.
func (p *personalKeys) find(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*domain.Auth, error) {
	if err := domain.ValidateOwner(ownerID); err != nil {
		return nil, err
	}
	a, err := p.repo.FindByOwnerAndGroup(ctx, gatewayID, ownerID, "")
	if err != nil {
		return nil, fmt.Errorf("auth: find personal key: %w", err)
	}
	return a, nil
}

func (p *personalKeys) ensureNotHybrid(ctx context.Context, gatewayID ids.GatewayID) error {
	gw, err := p.gateways.FindByID(ctx, gatewayID)
	if err != nil {
		return fmt.Errorf("auth: load gateway: %w", err)
	}
	if !gw.AllowsPersonal() {
		return consumerdomain.ErrHybridPersonal
	}
	return nil
}
