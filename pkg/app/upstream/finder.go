package upstream

import (
	"context"
	"errors"

	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var ErrInvalidCacheType = errors.New("invalid type assertion for upstream model")

type Finder interface {
	Find(ctx context.Context, gatewayID, upstreamID uuid.UUID) (*domainUpstream.Upstream, error)
}

type finder struct {
	repo        domainUpstream.Repository
	cache       cache.Client
	memoryCache *cache.TTLMap
	logger      *logrus.Logger
}

func NewFinder(repository domainUpstream.Repository, c cache.Client, logger *logrus.Logger) Finder {
	return &finder{
		repo:        repository,
		cache:       c,
		logger:      logger,
		memoryCache: c.GetTTLMap(cache.UpstreamTTLName),
	}
}

func (f *finder) Find(ctx context.Context, gatewayID, upstreamID uuid.UUID) (*domainUpstream.Upstream, error) {
	if upstream, err := f.getUpstreamFromMemoryCache(upstreamID.String()); err == nil {
		return upstream, nil
	} else if !errors.Is(err, ErrInvalidCacheType) {
		f.logger.WithError(err).Debug("memory cache read upstream failure")
	}
	if cachedUpstream, err := f.cache.GetUpstream(ctx, gatewayID.String(), upstreamID.String()); err == nil && cachedUpstream != nil {
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

func (f *finder) getUpstreamFromMemoryCache(upstreamID string) (*domainUpstream.Upstream, error) {
	if cachedValue, found := f.memoryCache.Get(upstreamID); found {
		if upstream, ok := cachedValue.(*domainUpstream.Upstream); ok {
			return upstream, nil
		}
		return nil, ErrInvalidCacheType
	}
	return nil, errors.New("upstream not found in memory cache")
}

func (f *finder) saveUpstreamToMemoryCache(ctx context.Context, upstream *domainUpstream.Upstream) {
	f.memoryCache.Set(upstream.ID.String(), upstream)
	err := f.cache.SaveUpstream(ctx, upstream.GatewayID.String(), upstream)
	if err != nil {
		f.logger.WithError(err).Warn("failed to save upstream to distributed cache")
	}
}
