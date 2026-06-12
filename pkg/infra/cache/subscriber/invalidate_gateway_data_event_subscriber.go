package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.InvalidateGatewayDataEvent] = (*InvalidateGatewayDataEventSubscriber)(nil)

type InvalidateGatewayDataEventSubscriber struct {
	logger            *slog.Logger
	cache             cache.Client
	gatewayCache      *cache.TTLMap
	consumerDataCache *cache.TTLMap
	loadBalancerCache *cache.TTLMap
	authCache         *cache.TTLMap
	consumerPathCache *cache.TTLMap
}

func NewInvalidateGatewayDataEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.InvalidateGatewayDataEvent] {
	return &InvalidateGatewayDataEventSubscriber{
		logger:            logger,
		cache:             c,
		gatewayCache:      c.GetTTLMap(cache.GatewayTTLName),
		consumerDataCache: c.GetTTLMap(cache.ConsumerDataTTLName),
		loadBalancerCache: c.GetTTLMap(cache.LoadBalancerTTLName),
		authCache:         c.GetTTLMap(cache.AuthTTLName),
		consumerPathCache: c.GetTTLMap(cache.ConsumerPathTTLName),
	}
}

func (s *InvalidateGatewayDataEventSubscriber) OnEvent(ctx context.Context, evt event.InvalidateGatewayDataEvent) error {
	s.logger.Info("invalidating gateway data cache", slog.String("gateway_id", evt.GatewayID))

	if s.gatewayCache != nil {
		s.gatewayCache.Delete(evt.GatewayID)
	}
	if s.consumerDataCache != nil {
		s.consumerDataCache.Delete(evt.GatewayID)
	}
	if s.loadBalancerCache != nil {
		s.loadBalancerCache.DeleteByPrefix(evt.GatewayID + ":")
	}
	if s.authCache != nil {
		s.authCache.Clear()
	}
	if s.consumerPathCache != nil {
		s.consumerPathCache.Clear()
	}

	if err := s.cache.DeleteAllByGatewayID(ctx, evt.GatewayID); err != nil {
		s.logger.Warn("failed to delete gateway keys from redis cache",
			slog.String("gateway_id", evt.GatewayID),
			slog.String("error", err.Error()),
		)
	}

	return nil
}
