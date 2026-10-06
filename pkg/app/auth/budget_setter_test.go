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

package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var budgetNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func ownedKey(t *testing.T, gwID ids.GatewayID) *domain.Auth {
	t.Helper()
	a, err := domain.NewOwnedAPIKeyAuth(gwID, "alice", budgetNow.Add(24*time.Hour), budgetNow.Add(-time.Hour))
	require.NoError(t, err)
	a.RawKey = ""
	return a
}

func newBudgetSetter(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, signaler *configsynctest.FakeSignaler) appauth.BudgetSetter {
	return appauth.NewBudgetSetter(repo, manager, publisher, newTestLogger(), signaler, func() time.Time { return budgetNow })
}

func TestBudgetSetter_SetsOrClearsTheBudgetOfAnOwnedKey(t *testing.T) {
	t.Parallel()
	for name, budget := range map[string]*domain.KeyBudget{
		"set":   {Max: 50, TimeWindow: domain.BudgetWindowCalendarMonth},
		"clear": nil,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			existing := ownedKey(t, gwID)
			existing.Budget = &domain.KeyBudget{Max: 5, TimeWindow: domain.BudgetWindowCalendarDay}
			hash, prefix, expiry := existing.KeyHash, existing.KeyPrefix, *existing.ExpiresAt
			stored := *existing
			stored.KeyHash = "rotated-meanwhile"
			stored.Budget = budget.Clone()

			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			repo.EXPECT().UpdateBudget(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
				return a.ID == existing.ID && a.GatewayID == gwID && a.UpdatedAt.Equal(budgetNow) &&
					(budget == nil && a.Budget == nil || budget != nil && a.Budget != nil && *a.Budget == *budget) &&
					a.KeyHash == hash && a.KeyPrefix == prefix && a.ExpiresAt.Equal(expiry)
			})).Return(&stored, nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()
			manager := newCacheManager()
			signaler := &configsynctest.FakeSignaler{}

			got, err := newBudgetSetter(repo, manager, publisher, signaler).
				SetBudget(context.Background(), appauth.SetBudgetInput{ID: existing.ID, GatewayID: gwID, Budget: budget})
			require.NoError(t, err)
			require.Same(t, &stored, got, "the stored row is the answer, a concurrent rotation included")
			cachedByID, _ := manager.GetTTLMap(cache.AuthTTLName).Get(existing.ID.String())
			require.Same(t, &stored, cachedByID)
			cachedByKey, _ := manager.GetTTLMap(cache.AuthKeyTTLName).Get(stored.KeyHash)
			require.Same(t, &stored, cachedByKey)
			require.Equal(t, 1, signaler.Count())
		})
	}
}

func TestBudgetSetter_WritesNothingItRefuses(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	monthly := &domain.KeyBudget{Max: 50, TimeWindow: domain.BudgetWindowCalendarMonth}
	for name, tc := range map[string]struct {
		found   func(t *testing.T) (*domain.Auth, error)
		gateway ids.GatewayID
		budget  *domain.KeyBudget
		want    error
	}{
		"unknown auth": {
			found:   func(*testing.T) (*domain.Auth, error) { return nil, domain.ErrNotFound },
			gateway: gwID, budget: monthly, want: domain.ErrNotFound,
		},
		"another gateway's key": {
			found:   func(t *testing.T) (*domain.Auth, error) { return ownedKey(t, ids.New[ids.GatewayKind]()), nil },
			gateway: gwID, budget: monthly, want: domain.ErrNotFound,
		},
		"application key": {
			found:   func(t *testing.T) (*domain.Auth, error) { return existingAPIKey(t, gwID), nil },
			gateway: gwID, budget: monthly, want: domain.ErrApplicationKey,
		},
		"clearing an application key": {
			found:   func(t *testing.T) (*domain.Auth, error) { return existingAPIKey(t, gwID), nil },
			gateway: gwID, want: domain.ErrApplicationKey,
		},
		"invalid budget": {
			found:   func(t *testing.T) (*domain.Auth, error) { return ownedKey(t, gwID), nil },
			gateway: gwID, budget: &domain.KeyBudget{Max: 50, TimeWindow: "30d"}, want: domain.ErrInvalidBudget,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			existing, findErr := tc.found(t)
			id := ids.New[ids.AuthKind]()
			if existing != nil {
				id = existing.ID
			}
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, id).Return(existing, findErr).Once()
			signaler := &configsynctest.FakeSignaler{}

			_, err := newBudgetSetter(repo, newCacheManager(), cachemocks.NewEventPublisher(t), signaler).
				SetBudget(context.Background(), appauth.SetBudgetInput{ID: id, GatewayID: tc.gateway, Budget: tc.budget})
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, signaler.Count())
		})
	}
}

func TestBudgetSetter_DoesNotSignalWhenTheWriteFails(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := ownedKey(t, gwID)
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().UpdateBudget(mock.Anything, mock.Anything).Return(nil, errors.New("boom")).Once()
	manager := newCacheManager()
	signaler := &configsynctest.FakeSignaler{}

	_, err := newBudgetSetter(repo, manager, cachemocks.NewEventPublisher(t), signaler).
		SetBudget(context.Background(), appauth.SetBudgetInput{ID: existing.ID, GatewayID: gwID, Budget: &domain.KeyBudget{Max: 1, TimeWindow: domain.BudgetWindowCalendarDay}})
	require.EqualError(t, err, "boom")
	require.Zero(t, signaler.Count())
	_, cached := manager.GetTTLMap(cache.AuthTTLName).Get(existing.ID.String())
	require.False(t, cached)
}
