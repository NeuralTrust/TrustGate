package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.InvalidateGatewayDataEvent] = (*InvalidateGatewayDataEventSubscriber)(nil)

// InvalidateGatewayDataEventSubscriber drops every in-process cache entry keyed
// by a gateway: the gateway entity, the aggregated consumer-data view, and any
// Redis key scoped to that gateway. It runs on each process so a mutation on the
// admin plane propagates to every proxy instance.
type InvalidateGatewayDataEventSubscriber struct {
	logger            *slog.Logger
	cache             cache.Client
	gatewayCache      *cache.TTLMap
	consumerDataCache *cache.TTLMap
	loadBalancerCache *cache.TTLMap
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
		// Load balancers are keyed by "<gatewayID>:<consumerID>"; drop every
		// balancer of this gateway so the next request rebuilds it from the
		// refreshed consumer/backend configuration.
		s.loadBalancerCache.DeleteByPrefix(evt.GatewayID + ":")
	}

	if err := s.cache.DeleteAllByGatewayID(ctx, evt.GatewayID); err != nil {
		s.logger.Warn("failed to delete gateway keys from redis cache",
			slog.String("gateway_id", evt.GatewayID),
			slog.String("error", err.Error()),
		)
	}

	return nil
}
