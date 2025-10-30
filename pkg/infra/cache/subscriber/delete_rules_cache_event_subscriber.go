package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type DeleteRulesEventSubscriber struct {
	logger      *logrus.Logger
	cache       cache.Cache
	memoryCache *cache.TTLMap
}

func NewDeleteRulesEventSubscriber(
	logger *logrus.Logger,
	c cache.Cache,
) infraCache.EventSubscriber[event.DeleteRulesCacheEvent] {
	return &DeleteRulesEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.GatewayTTLName),
	}
}

func (s DeleteRulesEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteRulesCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": evt.GatewayID,
	}).Debug("invalidating rules cache")

	s.memoryCache.Delete(evt.GatewayID)
	rulesKey := fmt.Sprintf(cache.RulesKeyPattern, evt.GatewayID)

	if err := s.cache.Delete(ctx, rulesKey); err != nil {
		s.logger.WithError(err).Warn("failed to delete rules from redis cache")
	}
	if err := s.cache.DeleteAllByGatewayID(ctx, evt.GatewayID); err != nil {
		s.logger.WithError(err).Warn("failed to delete plugin data from redis cache")
	}
	return nil
}
