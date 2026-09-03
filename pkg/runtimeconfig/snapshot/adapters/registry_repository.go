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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
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

// List returns a gateway's registries from the compiled snapshot. It is a read,
// so — unlike the write methods — it is served rather than rejected: the MCP
// Store's installer and scoper scan a gateway's registries by catalog code
// through it. The NameContains, Page and Size filter fields are honored;
// gateway id is required (a zero filter yields nothing).
func (r *registryRepository) List(_ context.Context, filter domain.ListFilter) ([]*domain.Registry, int, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, 0, nil
	}
	all := snap.RegistriesByGateway(filter.GatewayID)
	if name := strings.ToLower(strings.TrimSpace(filter.NameContains)); name != "" {
		filtered := all[:0:0]
		for _, reg := range all {
			if reg != nil && strings.Contains(strings.ToLower(reg.Name), name) {
				filtered = append(filtered, reg)
			}
		}
		all = filtered
	}
	total := len(all)
	page := paginate(all, filter.Page, filter.Size)
	cloned, err := cloneSlice(page)
	if err != nil {
		return nil, 0, err
	}
	return cloned, total, nil
}

// paginate returns the 1-based Page window of size Size. A non-positive size
// returns everything (the installer/scoper ask for a single large page).
func paginate(items []*domain.Registry, page, size int) []*domain.Registry {
	if size <= 0 {
		return items
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * size
	if start >= len(items) {
		return nil
	}
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

var _ domain.Repository = (*registryRepository)(nil)
