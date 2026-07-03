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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

type roleRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewRoleRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &roleRepository{store: store}
}

func (r *roleRepository) FindByID(_ context.Context, id ids.RoleID) (*domain.Role, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	role, ok := snap.RoleByID(id)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(role)
}

func (r *roleRepository) FindByIDs(_ context.Context, gatewayID ids.GatewayID, roleIDs []ids.RoleID) ([]*domain.Role, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.RolesByIDs(gatewayID, roleIDs))
}

func (r *roleRepository) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*domain.Role, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.RolesByGateway(gatewayID))
}

func (r *roleRepository) Save(_ context.Context, _ *domain.Role) error {
	return configsync.ErrReadOnly
}

func (r *roleRepository) Update(_ context.Context, _ *domain.Role) error {
	return configsync.ErrReadOnly
}

func (r *roleRepository) Delete(_ context.Context, _ ids.GatewayID, _ ids.RoleID) error {
	return configsync.ErrReadOnly
}

func (r *roleRepository) List(_ context.Context, _ domain.ListFilter) ([]*domain.Role, int, error) {
	return nil, 0, configsync.ErrReadOnly
}

func (r *roleRepository) AttachRegistry(_ context.Context, _ ids.RoleID, _ ids.RegistryID) error {
	return configsync.ErrReadOnly
}

func (r *roleRepository) DetachRegistry(_ context.Context, _ ids.RoleID, _ ids.RegistryID) error {
	return configsync.ErrReadOnly
}

func (r *roleRepository) DetachRegistryIfUnreferenced(_ context.Context, _ ids.GatewayID, _ ids.RoleID, _ ids.RegistryID) (*domain.Role, error) {
	return nil, configsync.ErrReadOnly
}

var _ domain.Repository = (*roleRepository)(nil)
