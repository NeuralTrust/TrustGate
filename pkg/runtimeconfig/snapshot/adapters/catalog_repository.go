package adapters

import (
	"context"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

type catalogRepository struct {
	store configsync.ConfigStore[*readmodel.Snapshot]
}

func NewCatalogRepository(store configsync.ConfigStore[*readmodel.Snapshot]) domain.Repository {
	return &catalogRepository{store: store}
}

func (r *catalogRepository) FindModel(_ context.Context, providerCode, slug string) (*domain.Model, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	m, ok := snap.CatalogModelByProviderSlug(providerCode, slug)
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	return cloneJSON(m)
}

func (r *catalogRepository) ListModelsByProviderCode(_ context.Context, providerCode string) ([]domain.Model, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	return cloneModels(snap.CatalogModelsByProviderCode(providerCode))
}

func (r *catalogRepository) ListProviders(_ context.Context) ([]domain.Provider, error) {
	snap, ok := snapshotFrom(r.store)
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	return cloneProviders(snap.Providers())
}

func (r *catalogRepository) UpsertProvider(_ context.Context, _ *domain.Provider) error {
	return configsync.ErrReadOnly
}

func (r *catalogRepository) UpsertModel(_ context.Context, _ *domain.Model) error {
	return configsync.ErrReadOnly
}

func (r *catalogRepository) DisableModelsExcept(_ context.Context, _ ids.ProviderID, _ string, _ []string) error {
	return configsync.ErrReadOnly
}

func cloneModels(src []*domain.Model) ([]domain.Model, error) {
	out := make([]domain.Model, 0, len(src))
	for _, m := range src {
		clone, err := cloneJSON(m)
		if err != nil {
			return nil, err
		}
		out = append(out, *clone)
	}
	return out, nil
}

func cloneProviders(src []*domain.Provider) ([]domain.Provider, error) {
	out := make([]domain.Provider, 0, len(src))
	for _, p := range src {
		clone, err := cloneJSON(p)
		if err != nil {
			return nil, err
		}
		out = append(out, *clone)
	}
	return out, nil
}

var _ domain.Repository = (*catalogRepository)(nil)
