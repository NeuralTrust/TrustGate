package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type DeleteUpstreamCacheEventSubscriber struct {
	logger        *logrus.Logger
	cache         cache.Client
	memoryCache   *cache.TTLMap
	lbMemoryCache *cache.TTLMap
}

func NewDeleteUpstreamCacheEventSubscriber(
	logger *logrus.Logger,
	c cache.Client,
) cache.EventSubscriber[event.DeleteUpstreamCacheEvent] {
	return &DeleteUpstreamCacheEventSubscriber{
		logger:        logger,
		cache:         c,
		memoryCache:   c.GetTTLMap(cache.UpstreamTTLName),
		lbMemoryCache: c.GetTTLMap(cache.LoadBalancerTTLName),
	}
}

func (s DeleteUpstreamCacheEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteUpstreamCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"upstreamID": evt.UpstreamID,
		"gatewayID":  evt.GatewayID,
	}).Debug("invalidating upstream cache")

	if s.memoryCache != nil {
		s.memoryCache.Delete(evt.UpstreamID)
	}
	if s.lbMemoryCache != nil {
		s.lbMemoryCache.Delete(evt.UpstreamID)
	}

	if err := s.cache.Delete(ctx, fmt.Sprintf(cache.UpstreamKeyPattern, evt.GatewayID, evt.UpstreamID)); err != nil {
		s.logger.WithError(err).Warn("failed to delete upstream from redis cache")
	}

	if err := s.cache.Delete(ctx, fmt.Sprintf(cache.UpstreamsKeyPattern, evt.GatewayID)); err != nil {
		s.logger.WithError(err).Warn("failed to delete upstream from redis cache")
	}

	return nil
}
