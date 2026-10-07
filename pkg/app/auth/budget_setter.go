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

// SetBudgetInput names the personal key whose budget changes.
type SetBudgetInput struct {
	ID        ids.AuthID
	GatewayID ids.GatewayID
	// Budget replaces the key's budget; nil clears it.
	Budget *domain.KeyBudget
}

//go:generate mockery --name=BudgetSetter --dir=. --output=./mocks --filename=auth_budget_setter_mock.go --case=underscore --with-expecter

// BudgetSetter sets or clears the spending limit of a personal key. The
// secret, the expiry and the links of the key stay as they are.
type BudgetSetter interface {
	SetBudget(ctx context.Context, in SetBudgetInput) (*domain.Auth, error)
}

var _ BudgetSetter = (*budgetSetter)(nil)

type budgetSetter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	now         func() time.Time
}

// NewBudgetSetter returns the BudgetSetter; now defaults to the UTC wall clock.
func NewBudgetSetter(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	now func() time.Time,
) BudgetSetter {
	return &budgetSetter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		now:         utcClock(now),
	}
}

func (s *budgetSetter) SetBudget(ctx context.Context, in SetBudgetInput) (*domain.Auth, error) {
	existing, err := s.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if existing.GatewayID != in.GatewayID {
		return nil, domain.ErrNotFound
	}
	if err := existing.SetBudget(in.Budget, s.now()); err != nil {
		return nil, err
	}
	stored, err := s.repo.UpdateBudget(ctx, existing)
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
