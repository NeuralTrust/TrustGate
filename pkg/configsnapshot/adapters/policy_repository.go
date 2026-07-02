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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

type policyRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewPolicyRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &policyRepository{store: store}
}

func (r *policyRepository) FindByID(_ context.Context, id ids.PolicyID) (*domain.Policy, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	p, ok := snap.PolicyByID(id)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(p)
}

func (r *policyRepository) FindByIDs(_ context.Context, gatewayID ids.GatewayID, policyIDs []ids.PolicyID) ([]*domain.Policy, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.PoliciesByIDs(gatewayID, policyIDs))
}

func (r *policyRepository) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*domain.Policy, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.PoliciesByGateway(gatewayID))
}

func (r *policyRepository) Save(_ context.Context, _ *domain.Policy) error {
	return configsync.ErrReadOnly
}

func (r *policyRepository) Update(_ context.Context, _ *domain.Policy) error {
	return configsync.ErrReadOnly
}

func (r *policyRepository) SetGlobal(_ context.Context, _ ids.GatewayID, _ ids.PolicyID, _ bool) error {
	return configsync.ErrReadOnly
}

func (r *policyRepository) Delete(_ context.Context, _ ids.GatewayID, _ ids.PolicyID) error {
	return configsync.ErrReadOnly
}

func (r *policyRepository) List(_ context.Context, _ domain.ListFilter) ([]*domain.Policy, int, error) {
	return nil, 0, configsync.ErrReadOnly
}

var _ domain.Repository = (*policyRepository)(nil)
