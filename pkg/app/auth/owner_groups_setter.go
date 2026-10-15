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

// SetOwnerGroupsInput names the personal key whose owner groups change.
type SetOwnerGroupsInput struct {
	ID        ids.AuthID
	GatewayID ids.GatewayID
	// Groups replaces the owner's groups; empty clears them.
	Groups []string
	// Email, when set, replaces the owner's email; empty clears it. Nil
	// leaves it as it is.
	Email *string
}

//go:generate mockery --name=OwnerGroupsSetter --dir=. --output=./mocks --filename=auth_owner_groups_setter_mock.go --case=underscore --with-expecter

// OwnerGroupsSetter records the directory groups of a personal key's owner,
// which the MCP Store reads in place of a session's groups claim, and their
// email, which the key's calls are shown under. The secret, the expiry, the
// budget and the links of the key stay as they are.
type OwnerGroupsSetter interface {
	SetOwnerGroups(ctx context.Context, in SetOwnerGroupsInput) (*domain.Auth, error)
}

var _ OwnerGroupsSetter = (*ownerGroupsSetter)(nil)

type ownerGroupsSetter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	now         func() time.Time
}

// NewOwnerGroupsSetter returns the OwnerGroupsSetter; now defaults to the UTC
// wall clock.
func NewOwnerGroupsSetter(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	now func() time.Time,
) OwnerGroupsSetter {
	return &ownerGroupsSetter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		now:         utcClock(now),
	}
}

func (s *ownerGroupsSetter) SetOwnerGroups(ctx context.Context, in SetOwnerGroupsInput) (*domain.Auth, error) {
	existing, err := s.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if existing.GatewayID != in.GatewayID {
		return nil, domain.ErrNotFound
	}
	now := s.now()
	if err := existing.SetOwnerGroups(in.Groups, now); err != nil {
		return nil, err
	}
	if in.Email != nil {
		if err := existing.SetOwnerEmail(*in.Email, now); err != nil {
			return nil, err
		}
	}
	stored, err := s.repo.UpdateOwner(ctx, existing)
	if err != nil {
		return nil, err
	}
	s.memoryCache.Set(stored.ID.String(), stored)
	if stored.KeyHash != "" {
		s.keyCache.Set(stored.KeyHash, stored)
	}
	invalidation.GatewayData(ctx, s.publisher, s.logger, stored.GatewayID)
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
	return stored, nil
}
