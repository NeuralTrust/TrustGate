package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.InvalidateBackendCacheEvent] = (*InvalidateBackendCacheEventSubscriber)(nil)

// InvalidateBackendCacheEventSubscriber drops the cached backend entity and the
// load balancer instance derived from it, forcing the next request to rebuild
// the load balancer from fresh backend data.
type InvalidateBackendCacheEventSubscriber struct {
	logger            *slog.Logger
	backendCache      *cache.TTLMap
	loadBalancerCache *cache.TTLMap
}

func NewInvalidateBackendCacheEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.InvalidateBackendCacheEvent] {
	return &InvalidateBackendCacheEventSubscriber{
		logger:            logger,
		backendCache:      c.GetTTLMap(cache.BackendTTLName),
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
	if s.loadBalancerCache != nil {
		s.loadBalancerCache.Delete(evt.BackendID)
	}

	return nil
}
