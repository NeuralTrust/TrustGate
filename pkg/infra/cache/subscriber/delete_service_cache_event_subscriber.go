package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type DeleteServiceCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       cache.Client
	memoryCache *cache.TTLMap
}

func NewDeleteServiceCacheEventSubscriber(
	logger *logrus.Logger,
	c cache.Client,
) cache.EventSubscriber[event.DeleteServiceCacheEvent] {
	return &DeleteServiceCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.ServiceTTLName),
	}
}

func (s DeleteServiceCacheEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteServiceCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"serviceID": evt.ServiceID,
		"gatewayID": evt.GatewayID,
	}).Debug("invalidating service cache")

	s.memoryCache.Delete(evt.ServiceID)

	if err := s.cache.Delete(ctx, fmt.Sprintf(cache.ServiceKeyPattern, evt.GatewayID, evt.ServiceID)); err != nil {
		s.logger.WithError(err).Warn("failed to delete service from redis cache")
	}

	if err := s.cache.Delete(ctx, fmt.Sprintf(cache.ServicesKeyPattern, evt.GatewayID)); err != nil {
		s.logger.WithError(err).Warn("failed to delete services from redis cache")
	}

	return nil
}
