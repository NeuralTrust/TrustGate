package adapters

import (
	"context"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

type authRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewAuthRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &authRepository{store: store}
}

func (r *authRepository) FindByID(_ context.Context, id ids.AuthID) (*domain.Auth, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	a, ok := snap.AuthByID(id)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneAuth(a)
}

func (r *authRepository) FindByIDs(_ context.Context, gatewayID ids.GatewayID, authIDs []ids.AuthID) ([]*domain.Auth, error) {
	if len(authIDs) == 0 {
		return nil, nil
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneAuths(snap.AuthsByIDs(gatewayID, authIDs))
}

func (r *authRepository) FindByAPIKeyHash(_ context.Context, keyHash string) (*domain.Auth, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	a, ok := snap.AuthByAPIKeyHash(keyHash)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneAuth(a)
}

func (r *authRepository) FindEnabledByTypes(_ context.Context, types []domain.Type) ([]*domain.Auth, error) {
	if len(types) == 0 {
		return nil, nil
	}
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneAuths(snap.AuthsEnabledByTypes(types))
}

func (r *authRepository) ListEnabledByGatewayAndType(_ context.Context, gatewayID ids.GatewayID, authType domain.Type) ([]*domain.Auth, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return cloneAuths(snap.AuthsEnabledByGatewayAndType(gatewayID, authType))
}

func (r *authRepository) Save(_ context.Context, _ *domain.Auth) error {
	return configsync.ErrReadOnly
}

func (r *authRepository) Update(_ context.Context, _ *domain.Auth) error {
	return configsync.ErrReadOnly
}

func (r *authRepository) Delete(_ context.Context, _ ids.GatewayID, _ ids.AuthID) error {
	return configsync.ErrReadOnly
}

func (r *authRepository) List(_ context.Context, _ domain.ListFilter) ([]*domain.Auth, int, error) {
	return nil, 0, configsync.ErrReadOnly
}

func cloneAuths(src []*domain.Auth) ([]*domain.Auth, error) {
	out := make([]*domain.Auth, 0, len(src))
	for _, a := range src {
		clone, err := cloneAuth(a)
		if err != nil {
			return nil, err
		}
		out = append(out, clone)
	}
	return out, nil
}

var _ domain.Repository = (*authRepository)(nil)
