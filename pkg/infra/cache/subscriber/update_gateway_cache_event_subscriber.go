package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type UpdateGatewayCacheEventSubscriber struct {
	logger       *logrus.Logger
	cacheService gateway.UpdateGatewayCache
	cache        *cache.Cache
	repo         *database.Repository
	memoryCache  *common.TTLMap
}

func NewUpdateGatewayCacheEventSubscriber(
	logger *logrus.Logger,
	cacheService gateway.UpdateGatewayCache,
	c *cache.Cache,
) infraCache.EventSubscriber[event.UpdateGatewayCacheEvent] {
	return &UpdateGatewayCacheEventSubscriber{
		logger:       logger,
		cacheService: cacheService,
		memoryCache:  c.GetTTLMap(cache.UpstreamTTLName),
	}
}

func (s UpdateGatewayCacheEventSubscriber) OnEvent(ctx context.Context, evt event.UpdateGatewayCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": evt.GatewayID,
	}).Debug("updating gateway cache")

	entity, err := s.repo.GetGateway(ctx, evt.GatewayID)
	if err != nil {
		s.logger.WithError(err).Warn("failed to fetch gateway from database")
	}

	if err := s.cacheService.Update(ctx, entity); err != nil {
		s.logger.WithError(err).Error("failed to cache gateway")
	}

	rulesKey := fmt.Sprintf(cache.RulesKeyPattern, evt.GatewayID)
	if err := s.cache.Delete(ctx, rulesKey); err != nil {
		return fmt.Errorf("failed to delete rules cache: %w", err)
	}

	s.memoryCache.Set(entity.ID, entity)

	return nil
}
