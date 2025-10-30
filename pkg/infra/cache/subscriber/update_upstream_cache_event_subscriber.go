package subscriber

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UpdateUpstreamCacheEventSubscriber struct {
	logger      *logrus.Logger
	cache       cache.Cache
	repository  upstream.Repository
	memoryCache *cache.TTLMap
}

func NewUpdateUpstreamCacheEventSubscriber(
	logger *logrus.Logger,
	c cache.Cache,
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

	upstreamIDUUID, err := uuid.Parse(evt.UpstreamID)
	if err != nil {
		return fmt.Errorf("failed to parse upstream ID: %v", err)
	}
	entity, err := s.repository.GetUpstream(ctx, upstreamIDUUID)
	if err != nil {
		s.logger.WithError(err).Warn("failed to fetch upstream from database")
	}

	if err := s.cache.SaveUpstream(ctx, evt.GatewayID, entity); err != nil {
		s.logger.WithError(err).Error("failed to cache upstream")
	}

	s.memoryCache.Set(entity.ID.String(), entity)

	return nil
}
