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

package keygroup_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	appkeygroup "github.com/NeuralTrust/TrustGate/pkg/app/keygroup"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/keygroup/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var budgetsNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type budgetsFixture struct {
	gw        ids.GatewayID
	repo      *mocks.Repository
	publisher *cachemocks.EventPublisher
	signaler  *configsynctest.FakeSignaler
	budgets   appkeygroup.Budgets
}

func newBudgetsFixture(t *testing.T) *budgetsFixture {
	t.Helper()
	f := &budgetsFixture{
		gw:        ids.New[ids.GatewayKind](),
		repo:      mocks.NewRepository(t),
		publisher: cachemocks.NewEventPublisher(t),
		signaler:  &configsynctest.FakeSignaler{},
	}
	f.budgets = appkeygroup.NewBudgets(f.repo, f.publisher, slog.New(slog.DiscardHandler), f.signaler, func() time.Time { return budgetsNow })
	return f
}

func (f *budgetsFixture) published() {
	f.publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: f.gw.String()}).Return(nil).Once()
}

func usd(v float64) *float64 { return &v }

func TestBudgets_SetStoresAndAnnounces(t *testing.T) {
	t.Parallel()
	f := newBudgetsFixture(t)
	f.repo.EXPECT().Upsert(mock.Anything, mock.MatchedBy(func(b *domain.Budget) bool {
		return b.GatewayID == f.gw && b.GroupID == "g-eng" && *b.MonthlyLimitUSD == 100 && b.MemberOverrides["alice"] == 5 &&
			b.Action == domain.ActionBlock && b.UpdatedAt.Equal(budgetsNow)
	})).RunAndReturn(func(_ context.Context, b *domain.Budget) (*domain.Budget, error) { return b, nil }).Once()
	f.published()

	stored, err := f.budgets.Set(context.Background(), appkeygroup.SetBudgetInput{
		GatewayID: f.gw, GroupID: " g-eng ", MonthlyLimitUSD: usd(100), MemberOverrides: map[string]float64{"alice": 5}, Action: "block",
	})
	require.NoError(t, err)
	require.Equal(t, "g-eng", stored.GroupID)
	require.Equal(t, 1, f.signaler.Count())
}

func TestBudgets_SetRefusesAnInvalidBudgetWithoutWriting(t *testing.T) {
	t.Parallel()
	f := newBudgetsFixture(t)
	_, err := f.budgets.Set(context.Background(), appkeygroup.SetBudgetInput{GatewayID: f.gw, GroupID: "g-eng", Action: "block"})
	require.ErrorIs(t, err, domain.ErrInvalidBudget)
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	require.Zero(t, f.signaler.Count())
}

func TestBudgets_DeleteAndList(t *testing.T) {
	t.Parallel()
	f := newBudgetsFixture(t)
	f.repo.EXPECT().Delete(mock.Anything, f.gw, "g-eng").Return(nil).Once()
	f.published()
	require.NoError(t, f.budgets.Delete(context.Background(), f.gw, "g-eng"))
	require.Equal(t, 1, f.signaler.Count())

	f.repo.EXPECT().Delete(mock.Anything, f.gw, "g-sre").Return(domain.ErrNotFound).Once()
	require.ErrorIs(t, f.budgets.Delete(context.Background(), f.gw, "g-sre"), domain.ErrNotFound)
	require.Equal(t, 1, f.signaler.Count(), "nothing changed, nothing announced")

	f.repo.EXPECT().ListByGateway(mock.Anything, f.gw).Return(nil, nil).Once()
	listed, err := f.budgets.List(context.Background(), f.gw)
	require.NoError(t, err)
	require.NotNil(t, listed)
	require.Empty(t, listed)
	f.repo.EXPECT().ListByGateway(mock.Anything, f.gw).Return(nil, errors.New("db down")).Once()
	_, err = f.budgets.List(context.Background(), f.gw)
	require.Error(t, err)
}
