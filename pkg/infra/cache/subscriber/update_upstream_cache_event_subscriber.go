package subscriber

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/sirupsen/logrus"
)

type UpdateUpstreamCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       *cache.Cache
	repository  upstream.Repository
	memoryCache *common.TTLMap
}

func NewUpdateUpstreamCacheEventSubscriber(
	logger *logrus.Logger,
	c *cache.Cache,
	repository upstream.Repository,
) infraCache.EventSubscriber[event.UpdateUpstreamCacheEvent] {
	return &UpdateUpstreamCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		repository:  repository,
		memoryCache: c.GetTTLMap(cache.UpstreamTTLName),
	}
}

func (s UpdateUpstreamCacheEventSubscriber) OnEvent(ctx context.Context, evt event.UpdateUpstreamCacheEvent) error {
	s.logger.WithFields(logrus.Fields{
		"upstreamID": evt.UpstreamID,
		"gatewayID":  evt.GatewayID,
	}).Debug("updating upstream cache")

	entity, err := s.repository.GetUpstream(ctx, evt.UpstreamID)
	if err != nil {
		s.logger.WithError(err).Warn("failed to fetch upstream from database")
	}

	if err := s.cache.SaveUpstream(ctx, evt.GatewayID, entity); err != nil {
		s.logger.WithError(err).Error("failed to cache upstream")
	}

	s.memoryCache.Set(entity.ID, entity)

	return nil
}
