package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.InvalidateBackendCacheEvent] = (*InvalidateBackendCacheEventSubscriber)(nil)

// InvalidateBackendCacheEventSubscriber drops the cached backend entity, the
// aggregated consumer-data view that embeds the backend, and every load balancer
// of the gateway (balancers embed backend config), forcing the next request to
// rebuild them from fresh backend data.
type InvalidateBackendCacheEventSubscriber struct {
	logger            *slog.Logger
	backendCache      *cache.TTLMap
	consumerDataCache *cache.TTLMap
	loadBalancerCache *cache.TTLMap
}

func NewInvalidateBackendCacheEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.InvalidateBackendCacheEvent] {
	return &InvalidateBackendCacheEventSubscriber{
		logger:            logger,
		backendCache:      c.GetTTLMap(cache.BackendTTLName),
		consumerDataCache: c.GetTTLMap(cache.ConsumerDataTTLName),
		loadBalancerCache: c.GetTTLMap(cache.LoadBalancerTTLName),
	}
}

func (s *InvalidateBackendCacheEventSubscriber) OnEvent(_ context.Context, evt event.InvalidateBackendCacheEvent) error {
	s.logger.Info("invalidating backend cache",
		slog.String("gateway_id", evt.GatewayID),
		slog.String("backend_id", evt.BackendID),
	)

	if s.backendCache != nil {
		s.backendCache.Delete(evt.BackendID)
	}
	if s.consumerDataCache != nil {
		s.consumerDataCache.Delete(evt.GatewayID)
	}
	if s.loadBalancerCache != nil {
		// Balancers are keyed by "<gatewayID>:<consumerID>" and embed backend
		// config, so evict all of this gateway's balancers by prefix.
		s.loadBalancerCache.DeleteByPrefix(evt.GatewayID + ":")
	}

	return nil
}
