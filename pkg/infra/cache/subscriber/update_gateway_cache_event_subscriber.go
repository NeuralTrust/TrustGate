package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UpdateGatewayCacheEventSubscriber struct {
	logger       *logrus.Logger
	cacheService gateway.UpdateGatewayCache
	cache        *cache.Cache
	repo         domainGateway.Repository
	memoryCache  *common.TTLMap
}

func NewUpdateGatewayCacheEventSubscriber(
	logger *logrus.Logger,
	cacheService gateway.UpdateGatewayCache,
	c *cache.Cache,
	repo domainGateway.Repository,
) infraCache.EventSubscriber[event.UpdateGatewayCacheEvent] {
	return &UpdateGatewayCacheEventSubscriber{
		logger:       logger,
		cacheService: cacheService,
		cache:        c,
		repo:         repo,
		memoryCache:  c.GetTTLMap(cache.UpstreamTTLName),
	}
}

func (s UpdateGatewayCacheEventSubscriber) OnEvent(ctx context.Context, evt event.UpdateGatewayCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": evt.GatewayID,
	}).Debug("updating gateway cache")
	gatewayUUID, err := uuid.Parse(evt.GatewayID)
	if err != nil {
		return fmt.Errorf("failed to parse gateway ID: %v", err)
	}
	entity, err := s.repo.Get(ctx, gatewayUUID)
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

	s.memoryCache.Set(entity.ID.String(), entity)

	if err := s.cache.DeleteAllPluginsData(ctx, evt.GatewayID); err != nil {
		s.logger.WithError(err).Warn("failed to delete plugin data from redis cache")
	}

	return nil
}
