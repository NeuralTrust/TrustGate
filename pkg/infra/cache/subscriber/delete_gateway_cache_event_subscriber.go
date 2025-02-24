package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type DeleteGatewayCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       *cache.Cache
	memoryCache *common.TTLMap
}

func NewDeleteGatewayCacheEventSubscriber(
	logger *logrus.Logger,
	c *cache.Cache,
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

	if err := s.cache.Delete(ctx, fmt.Sprintf(cache.GatewayKeyPattern, evt.GatewayID)); err != nil {
		s.logger.WithError(err).Warn("failed to delete gateway from redis cache")
	}
	return nil
}
