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

// Package keygroup manages the budgets of directory groups' keys: the admin's
// side of what the proxy enforces on /store/v1 for a group key.
package keygroup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// SetBudgetInput is the budget a group is held to on a gateway. Nil limits are
// no limit; it must set at least one.
type SetBudgetInput struct {
	GatewayID             ids.GatewayID
	GroupID               string
	MonthlyLimitUSD       *float64
	MemberMonthlyLimitUSD *float64
	MemberOverrides       map[string]float64
	Action                string
}

//go:generate mockery --name=Budgets --dir=. --output=./mocks --filename=key_group_budgets_mock.go --case=underscore --with-expecter

// Budgets lists, sets and clears the budgets of a gateway's directory groups.
// A change reaches the proxies as a key change does: every replica drops the
// gateway's data and the config snapshot is recompiled.
type Budgets interface {
	List(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Budget, error)
	// Set creates or replaces the group's budget, keeping its creation time.
	Set(ctx context.Context, in SetBudgetInput) (*domain.Budget, error)
	// Delete clears the group's budget, or answers domain.ErrNotFound.
	Delete(ctx context.Context, gatewayID ids.GatewayID, groupID string) error
}

var _ Budgets = (*budgets)(nil)

type budgets struct {
	repo      domain.Repository
	publisher cache.EventPublisher
	logger    *slog.Logger
	signaler  configsyncport.SnapshotSignaler
	now       func() time.Time
}

// NewBudgets returns the Budgets use case; now defaults to the UTC wall clock.
func NewBudgets(
	repo domain.Repository,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	now func() time.Time,
) Budgets {
	if now == nil {
		now = time.Now
	}
	return &budgets{
		repo:      repo,
		publisher: publisher,
		logger:    logger,
		signaler:  signaler,
		now:       func() time.Time { return now().UTC() },
	}
}

func (b *budgets) List(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Budget, error) {
	items, err := b.repo.ListByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("key group budgets: list: %w", err)
	}
	if items == nil {
		items = []*domain.Budget{}
	}
	return items, nil
}

func (b *budgets) Set(ctx context.Context, in SetBudgetInput) (*domain.Budget, error) {
	budget, err := domain.NewBudget(in.GatewayID, in.GroupID, in.MonthlyLimitUSD, in.MemberMonthlyLimitUSD, in.MemberOverrides, in.Action, b.now())
	if err != nil {
		return nil, err
	}
	stored, err := b.repo.Upsert(ctx, budget)
	if err != nil {
		return nil, err
	}
	b.changed(ctx, in.GatewayID)
	return stored, nil
}

func (b *budgets) Delete(ctx context.Context, gatewayID ids.GatewayID, groupID string) error {
	if err := b.repo.Delete(ctx, gatewayID, groupID); err != nil {
		return err
	}
	b.changed(ctx, gatewayID)
	return nil
}

// changed tells every replica, and the data planes through the snapshot, that
// the gateway's budgets are not what they cached.
func (b *budgets) changed(ctx context.Context, gatewayID ids.GatewayID) {
	invalidation.GatewayData(ctx, b.publisher, b.logger, gatewayID)
	if b.signaler != nil {
		b.signaler.Signal(ctx)
	}
}
