package upstream

import (
	"context"
	"github.com/NeuralTrust/TrustGate/pkg/models"
)

type Finder interface {
	FindByID(ctx context.Context, serviceID string) (*models.Upstream, error)
}

type finder struct {
	repo Repository
}

func NewFinder(repository Repository) Finder {
	return &finder{
		repo: repository,
	}
}

func (f *finder) FindByID(ctx context.Context, upstreamID string) (*models.Upstream, error) {
	upstreamModel, err := f.repo.GetUpstream(ctx, upstreamID)
	if err != nil {
		return nil, err
	}
	return upstreamModel, nil
}
