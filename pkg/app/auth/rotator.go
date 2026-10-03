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
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// ExpiryChange is an expiry a caller asked to change to.
//
// A nil *ExpiryChange leaves the stored expiry as it is, which is what a caller
// that did not mention expiry means; a non-nil one carrying a nil At clears the
// expiry. Without the distinction, "rotate this key" and "rotate this key and
// let it live forever" would be the same request.
type ExpiryChange struct {
	At *time.Time
}

type RotateInput struct {
	ID        ids.AuthID
	GatewayID ids.GatewayID
	Expiry    *ExpiryChange
}

//go:generate mockery --name=Rotator --dir=. --output=./mocks --filename=auth_rotator_mock.go --case=underscore --with-expecter

// Rotator replaces the secret of an api_key auth, keeping the auth itself.
//
// Revoking a key and issuing another one is not the same operation: it leaves
// the application without a credential in between, and whatever the old key was
// attached to has to be attached again. Rotating changes the secret and nothing
// else, so the only thing that has to reach the caller's clients is the new
// secret.
type Rotator interface {
	Rotate(ctx context.Context, in RotateInput) (*domain.Auth, error)
}

var _ Rotator = (*rotator)(nil)

type rotator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
}

func NewRotator(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) Rotator {
	return &rotator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
	}
}

func (r *rotator) Rotate(ctx context.Context, in RotateInput) (*domain.Auth, error) {
	existing, err := r.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if existing.GatewayID != in.GatewayID {
		return nil, domain.ErrNotFound
	}

	previousHash, err := existing.RotateAPIKey()
	if err != nil {
		return nil, err
	}
	if in.Expiry != nil {
		if err := existing.SetExpiry(in.Expiry.At); err != nil {
			return nil, err
		}
	}
	if err := r.repo.Update(ctx, existing); err != nil {
		return nil, err
	}

	// The old digest goes first: it is what the proxy looks a presented key up
	// by, and a rotation that left it behind would keep the secret it replaced
	// working for as long as the entry lived.
	if previousHash != "" {
		r.keyCache.Delete(previousHash)
	}
	r.memoryCache.Set(existing.ID.String(), existing)
	r.keyCache.Set(existing.KeyHash, existing)
	invalidation.GatewayData(ctx, r.publisher, r.logger, existing.GatewayID)
	if r.signaler != nil {
		r.signaler.Signal(ctx)
	}
	return existing, nil
}
