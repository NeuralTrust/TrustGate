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

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/configsync"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type registryRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewRegistryRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &registryRepository{store: store}
}

func (r *registryRepository) FindByID(_ context.Context, id ids.RegistryID) (*domain.Registry, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	reg, ok := snap.RegistryByID(id)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(reg)
}

func (r *registryRepository) FindByIDs(_ context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) ([]*domain.Registry, error) {
	if len(registryIDs) == 0 {
		return nil, nil
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.RegistriesByIDs(gatewayID, registryIDs))
}

func (r *registryRepository) Save(_ context.Context, _ *domain.Registry) error {
	return configsync.ErrReadOnly
}

func (r *registryRepository) Update(_ context.Context, _ *domain.Registry) error {
	return configsync.ErrReadOnly
}

func (r *registryRepository) Delete(_ context.Context, _ ids.GatewayID, _ ids.RegistryID) error {
	return configsync.ErrReadOnly
}

func (r *registryRepository) List(_ context.Context, _ domain.ListFilter) ([]*domain.Registry, int, error) {
	return nil, 0, configsync.ErrReadOnly
}

var _ domain.Repository = (*registryRepository)(nil)
