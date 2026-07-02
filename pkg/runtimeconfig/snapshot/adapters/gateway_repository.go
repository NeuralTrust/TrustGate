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

var _ domain.Repository = (*gatewayRepository)(nil)
