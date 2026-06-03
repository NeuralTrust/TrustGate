package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.InvalidateRegistryCacheEvent] = (*InvalidateRegistryCacheEventSubscriber)(nil)

// InvalidateRegistryCacheEventSubscriber drops the cached backend entity, the
// aggregated consumer-data view that embeds the backend, and every load balancer
// of the gateway (balancers embed backend config), forcing the next request to
// rebuild them from fresh backend data.
type InvalidateRegistryCacheEventSubscriber struct {
	logger            *slog.Logger
	backendCache      *cache.TTLMap
	consumerDataCache *cache.TTLMap
	loadBalancerCache *cache.TTLMap
}

func NewInvalidateRegistryCacheEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.InvalidateRegistryCacheEvent] {
	return &InvalidateRegistryCacheEventSubscriber{
		logger:            logger,
		backendCache:      c.GetTTLMap(cache.RegistryTTLName),
		consumerDataCache: c.GetTTLMap(cache.ConsumerDataTTLName),
		loadBalancerCache: c.GetTTLMap(cache.LoadBalancerTTLName),
	}
}

func (s *InvalidateRegistryCacheEventSubscriber) OnEvent(_ context.Context, evt event.InvalidateRegistryCacheEvent) error {
	s.logger.Info("invalidating backend cache",
		slog.String("gateway_id", evt.GatewayID),
		slog.String("registry_id", evt.RegistryID),
	)

	if s.backendCache != nil {
		s.backendCache.Delete(evt.RegistryID)
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
