package upstream

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/sirupsen/logrus"
)

var ErrInvalidCacheType = errors.New("invalid type assertion for upstream model")

type Finder interface {
	Find(ctx context.Context, gatewayID, upstreamID string) (*models.Upstream, error)
}

type finder struct {
	repo        domainUpstream.Repository
	cache       *cache.Cache
	memoryCache *common.TTLMap
	logger      *logrus.Logger
}

func NewFinder(repository domainUpstream.Repository, cache *cache.Cache, logger *logrus.Logger) Finder {
	return &finder{
		repo:        repository,
		cache:       cache,
		logger:      logger,
		memoryCache: cache.CreateTTLMap("upstream", common.UpstreamCacheTTL),
	}
}

func (f *finder) Find(ctx context.Context, gatewayID, upstreamID string) (*models.Upstream, error) {
	if upstream, err := f.getUpstreamFromMemoryCache(upstreamID); err == nil {
		return upstream, nil
	} else if !errors.Is(err, ErrInvalidCacheType) {
		f.logger.WithError(err).Warn("memory cache read upstream failure")
	}
	if cachedUpstream, err := f.cache.GetUpstream(ctx, gatewayID, upstreamID); err == nil && cachedUpstream != nil {
		f.saveUpstreamToMemoryCache(ctx, cachedUpstream)
		return cachedUpstream, nil
	} else if err != nil {
		f.logger.WithError(err).Warn("distributed cache read upstream failure")
	}
	upstream, err := f.repo.GetUpstream(ctx, upstreamID)
	if err != nil {
		f.logger.WithError(err).Error("failed to fetch upstream from repository")
		return nil, err
	}
	f.saveUpstreamToMemoryCache(ctx, upstream)
	return upstream, nil
}

func (f *finder) getUpstreamFromMemoryCache(upstreamID string) (*models.Upstream, error) {
	if cachedValue, found := f.memoryCache.Get(upstreamID); found {
		if upstream, ok := cachedValue.(*models.Upstream); ok {
			return upstream, nil
		}
		return nil, ErrInvalidCacheType
	}
	return nil, errors.New("upstream not found in memory cache")
}

func (f *finder) saveUpstreamToMemoryCache(ctx context.Context, upstream *models.Upstream) {
	f.memoryCache.Set(upstream.ID, upstream)
	err := f.cache.SaveUpstream(ctx, upstream.GatewayID, upstream)
	if err != nil {
		f.logger.WithError(err).Warn("failed to save upstream to distributed cache")
	}
}
