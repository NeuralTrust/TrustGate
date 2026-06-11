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
		// Load balancers are keyed by "<gatewayID>:<consumerID>"; drop every
		// balancer of this gateway so the next request rebuilds it from the
		// refreshed consumer/backend configuration.
		s.loadBalancerCache.DeleteByPrefix(evt.GatewayID + ":")
	}
	if s.authCache != nil {
		// Auth entries are cached both per-ID and as cross-gateway candidate
		// lists ("enabled:oauth2"/"enabled:mtls") consumed by the credential
		// chain and the OAuth AS facade. The event does not carry auth IDs,
		// so clear the whole map: auth mutations are rare and a stale list
		// here makes the AS metadata flap (e.g. "multiple authorization
		// servers" long after a duplicate was deleted).
		s.authCache.Clear()
	}
	if s.consumerPathCache != nil {
		// Path matches are keyed by "host|path" and may span gateways, so
		// the whole index is rebuilt on any gateway mutation.
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
