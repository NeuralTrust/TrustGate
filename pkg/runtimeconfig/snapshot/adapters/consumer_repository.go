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

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

type consumerRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewConsumerRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &consumerRepository{store: store}
}

func (r *consumerRepository) FindByID(_ context.Context, id ids.ConsumerID) (*domain.Consumer, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	c, ok := snap.ConsumerByID(id)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(c)
}

func (r *consumerRepository) FindActiveBySlug(_ context.Context, slug string) (*domain.Consumer, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	c, ok := snap.ConsumerActiveBySlug(slug)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneJSON(c)
}

func (r *consumerRepository) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*domain.Consumer, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.ConsumersByGateway(gatewayID))
}

func (r *consumerRepository) ListByAuthID(_ context.Context, authID ids.AuthID) ([]*domain.Consumer, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneSlice(snap.ConsumersByAuthID(authID))
}

func (r *consumerRepository) Save(_ context.Context, _ *domain.Consumer) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) Update(_ context.Context, _ *domain.Consumer) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) Delete(_ context.Context, _ ids.GatewayID, _ ids.ConsumerID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) List(_ context.Context, _ domain.ListFilter) ([]*domain.Consumer, int, error) {
	return nil, 0, configsync.ErrReadOnly
}

func (r *consumerRepository) AttachRegistry(_ context.Context, _ ids.ConsumerID, _ ids.RegistryID, _ *int) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) DetachRegistry(_ context.Context, _ ids.ConsumerID, _ ids.RegistryID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) DetachRegistryIfUnreferenced(_ context.Context, _ ids.GatewayID, _ ids.ConsumerID, _ ids.RegistryID) (*domain.Consumer, error) {
	return nil, configsync.ErrReadOnly
}

func (r *consumerRepository) AttachRole(_ context.Context, _ ids.ConsumerID, _ ids.RoleID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) DetachRole(_ context.Context, _ ids.ConsumerID, _ ids.RoleID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) AttachAuth(_ context.Context, _ ids.ConsumerID, _ ids.AuthID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) DetachAuth(_ context.Context, _ ids.ConsumerID, _ ids.AuthID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) AttachPolicy(_ context.Context, _ ids.ConsumerID, _ ids.PolicyID) error {
	return configsync.ErrReadOnly
}

func (r *consumerRepository) DetachPolicy(_ context.Context, _ ids.ConsumerID, _ ids.PolicyID) error {
	return configsync.ErrReadOnly
}

var _ domain.Repository = (*consumerRepository)(nil)
