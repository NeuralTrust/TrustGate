package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.DeleteGatewayCacheEvent] = (*DeleteGatewayCacheEventSubscriber)(nil)

type DeleteGatewayCacheEventSubscriber struct {
	logger      *slog.Logger
	cache       cache.Client
	memoryCache *cache.TTLMap
}

func NewDeleteGatewayCacheEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.DeleteGatewayCacheEvent] {
	return &DeleteGatewayCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.GatewayTTLName),
	}
}

func (s *DeleteGatewayCacheEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteGatewayCacheEvent) error {
	s.logger.Info("invalidating gateway cache", slog.String("gateway_id", evt.GatewayID))

	if s.memoryCache != nil {
		deleteGatewayAliases(s.memoryCache, evt.GatewayID)
	}

	if err := s.cache.DeleteAllByGatewayID(ctx, evt.GatewayID); err != nil {
		s.logger.Warn("failed to delete gateway from redis cache",
			slog.String("gateway_id", evt.GatewayID),
			slog.String("error", err.Error()),
		)
	}

	return nil
}
