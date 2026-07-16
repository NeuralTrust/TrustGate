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

func (r *gatewayRepository) Update(_ context.Context, _ *domain.Gateway) error {
	return configsync.ErrReadOnly
}

func (r *gatewayRepository) Delete(_ context.Context, _ ids.GatewayID) error {
	return configsync.ErrReadOnly
}

func (r *gatewayRepository) List(_ context.Context, _ domain.ListFilter) ([]*domain.Gateway, int, error) {
	return nil, 0, configsync.ErrReadOnly
}

func (r *gatewayRepository) CountByTenantID(_ context.Context, _ string) (int, error) {
	return 0, configsync.ErrReadOnly
}

var _ domain.Repository = (*gatewayRepository)(nil)
