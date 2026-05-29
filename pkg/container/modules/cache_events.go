package modules

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/channel"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/subscriber"
	"go.uber.org/dig"
)

// CacheEvents wires the Redis pub/sub invalidation pipeline: a publisher used by
// the mutating application services and a listener plus subscribers that drop
// stale in-process cache entries across every process.
func CacheEvents(c *container.Container) error {
	if err := c.Provide(func(client cache.Client) cache.EventPublisher {
		return cache.NewRedisEventPublisher(client, channel.GatewayEventsChannel)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(logger *slog.Logger, client cache.Client) cache.EventListener {
		return cache.NewRedisEventListener(logger, client, event.GetEventsRegistry())
	}); err != nil {
		return err
	}
	if err := c.Provide(subscriber.NewInvalidateGatewayDataEventSubscriber); err != nil {
		return err
	}
	return c.Provide(subscriber.NewInvalidateBackendCacheEventSubscriber)
}

// CacheEventListenerParams collects everything StartCacheEventListener needs.
type CacheEventListenerParams struct {
	dig.In
	Logger          *slog.Logger
	Listener        cache.EventListener
	GatewayDataSub  cache.EventSubscriber[event.InvalidateGatewayDataEvent]
	BackendCacheSub cache.EventSubscriber[event.InvalidateBackendCacheEvent]
}

// StartCacheEventListener registers the cache invalidation subscribers and
// starts the Redis pub/sub listener in a background goroutine. It is meant to be
// invoked once per process (admin and proxy) at boot.
func StartCacheEventListener(ctx context.Context, p CacheEventListenerParams) {
	cache.RegisterEventSubscriber(p.Listener, p.GatewayDataSub)
	cache.RegisterEventSubscriber(p.Listener, p.BackendCacheSub)

	go p.Listener.Listen(ctx, channel.GatewayEventsChannel)
	p.Logger.Info("cache event listener started", slog.String("channel", string(channel.GatewayEventsChannel)))
}
