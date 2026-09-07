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

package adapters

import (
	"context"
	"sort"
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

type gatewayRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewGatewayRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &gatewayRepository{store: store}
}

func (r *gatewayRepository) FindByID(_ context.Context, id ids.GatewayID) (*domain.Gateway, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	g, ok := snap.GatewayByID(id)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(g)
}

func (r *gatewayRepository) FindBySlug(_ context.Context, slug string) (*domain.Gateway, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	g, ok := snap.GatewayBySlug(slug)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(g)
}

func (r *gatewayRepository) FindByDomain(_ context.Context, host string) (*domain.Gateway, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	g, ok := snap.GatewayByDomain(host)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(g)
}

func (r *gatewayRepository) Save(_ context.Context, _ *domain.Gateway) error {
	return configsync.ErrReadOnly
}

func (r *gatewayRepository) SaveWithTenantCap(_ context.Context, _ *domain.Gateway, _ string, _ int) error {
	return configsync.ErrReadOnly
}

func (r *gatewayRepository) Update(_ context.Context, _ *domain.Gateway) error {
	return configsync.ErrReadOnly
}

func (r *gatewayRepository) UpdateWithTenantCap(_ context.Context, _ *domain.Gateway, _ string, _ int) error {
	return configsync.ErrReadOnly
}

// A dbless data plane is fed by config-sync, so entitlements arrive with the
// snapshot rather than being stamped here.
func (r *gatewayRepository) RestampEntitlementsByTenantID(
	_ context.Context,
	_ string,
	_ domain.Entitlements,
) ([]domain.RestampedGateway, error) {
	return nil, configsync.ErrReadOnly
}

func (r *gatewayRepository) Delete(_ context.Context, _ ids.GatewayID) error {
	return configsync.ErrReadOnly
}

func (r *gatewayRepository) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Gateway, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return []*domain.Gateway{}, 0, nil
	}
	data := snap.Data()
	matched := make([]domain.Gateway, 0, len(data.Gateways))
	needle := strings.ToLower(strings.TrimSpace(filter.SlugContains))
	for _, gateway := range data.Gateways {
		if needle != "" && !strings.Contains(strings.ToLower(gateway.Slug), needle) {
			continue
		}
		if filter.TenantID != "" && gateway.TenantID() != filter.TenantID {
			continue
		}
		matched = append(matched, gateway)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].ID.String() < matched[j].ID.String()
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})
	total := len(matched)
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Size < 1 {
		filter.Size = 20
	}
	start := min((filter.Page-1)*filter.Size, total)
	end := min(start+filter.Size, total)
	items := make([]*domain.Gateway, 0, end-start)
	for i := start; i < end; i++ {
		cloned, err := cloneJSON(&matched[i])
		if err != nil {
			return nil, 0, err
		}
		items = append(items, cloned)
	}
	return items, total, nil
}

func (r *gatewayRepository) CountByTenantID(ctx context.Context, tenantID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return 0, nil
	}
	count := 0
	for _, gateway := range snap.Data().Gateways {
		if gateway.TenantID() == tenantID {
			count++
		}
	}
	return count, nil
}

var _ domain.Repository = (*gatewayRepository)(nil)
