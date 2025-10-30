package subscriber

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type UpdateServiceCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       cache.Cache
	repository  service.Repository
	memoryCache *cache.TTLMap
}

func NewUpdateServiceCacheEventSubscriber(
	logger *logrus.Logger,
	c cache.Cache,
	repository service.Repository,
) infraCache.EventSubscriber[event.UpdateServiceCacheEvent] {
	return &UpdateServiceCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.ServiceTTLName),
		repository:  repository,
	}
}

func (s UpdateServiceCacheEventSubscriber) OnEvent(ctx context.Context, evt event.UpdateServiceCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"serviceID": evt.ServiceID,
		"gatewayID": evt.GatewayID,
	}).Debug("updating upstream cache")

	entity, err := s.repository.Get(ctx, evt.ServiceID)
	if err != nil {
		s.logger.WithError(err).Warn("failed to fetch service from database")
	}

	if err := s.cache.SaveService(ctx, evt.GatewayID, entity); err != nil {
		s.logger.WithError(err).Error("failed to cache service")
	}

	s.memoryCache.Set(entity.ID.String(), entity)

	return nil
}
