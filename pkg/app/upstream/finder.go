package upstream

import (
	"context"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/models"
)

type Finder interface {
	Find(ctx context.Context, gatewayID string, upstreamID string) (*models.Upstream, error)
}

type finder struct {
	repo  domainUpstream.Repository
	cache *cache.Cache
}

func NewFinder(repository domainUpstream.Repository, cache *cache.Cache) Finder {
	return &finder{
		repo:  repository,
		cache: cache,
	}
}

func (f *finder) Find(ctx context.Context, gatewayID string, upstreamID string) (*models.Upstream, error) {
	// Check cache first
	upstreamCache, err := f.cache.GetUpstream(ctx, gatewayID, upstreamID)
	if err != nil {
		return nil, err
	}
	if upstreamCache != nil {
		return upstreamCache, nil
	}
	upstreamModel, err := f.repo.GetUpstream(ctx, upstreamID)
	if err != nil {
		return nil, err
	}
	return upstreamModel, nil
}
