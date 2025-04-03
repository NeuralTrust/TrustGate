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

type DeleteApiKeyCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       *cache.Cache
	memoryCache *common.TTLMap
}

func NewDeleteApiKeyCacheEventSubscriber(
	logger *logrus.Logger,
	c *cache.Cache,
) infraCache.EventSubscriber[event.DeleteKeyCacheEvent] {
	return &DeleteApiKeyCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.ApiKeyTTLName),
	}
}

func (s DeleteApiKeyCacheEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteKeyCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"apiKey": evt.ApiKey,
	}).Debug("invalidating apikey cache")

	s.memoryCache.Delete(evt.ApiKeyID)
	s.memoryCache.Delete(evt.ApiKey)

	if err := s.cache.Delete(ctx, fmt.Sprintf(cache.ApiKeyPattern, evt.GatewayID, evt.ApiKey)); err != nil {
		s.logger.WithError(err).Warn("failed to delete apikey from redis cache")
	}
	return nil
}
