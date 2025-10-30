package subscriber

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type DeleteGatewayCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       cache.Cache
	memoryCache *cache.TTLMap
}

func NewDeleteGatewayCacheEventSubscriber(
	logger *logrus.Logger,
	c cache.Cache,
) infraCache.EventSubscriber[event.DeleteGatewayCacheEvent] {
	return &DeleteGatewayCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.GatewayTTLName),
	}
}

func (s DeleteGatewayCacheEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteGatewayCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": evt.GatewayID,
	}).Debug("invalidating gateway cache")

	s.memoryCache.Delete(evt.GatewayID)

	if err := s.cache.DeleteAllByGatewayID(ctx, evt.GatewayID); err != nil {
		s.logger.WithError(err).Warn("failed to delete gateway from redis cache")
	}

	return nil
}
