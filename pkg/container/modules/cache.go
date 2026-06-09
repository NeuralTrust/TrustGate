package modules

import (
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
)

func Cache(c *container.Container) error {
	if err := c.Provide(func(cfg *config.Config) *cache.TTLMapManager {
		mgr := cache.NewTTLMapManager(cfg.Cache.LocalTTL)
		initializeMemoryCache(mgr)
		return mgr
	}); err != nil {
		return err
	}
	return c.Provide(func(
		cfg *config.Config,
		mgr *cache.TTLMapManager,
		logger *slog.Logger,
	) (cache.Client, error) {
		return cache.NewClient(cache.Config{
			Host:              cfg.Redis.Host,
			Port:              cfg.Redis.Port,
			Password:          cfg.Redis.Password,
			DB:                cfg.Redis.DB,
			TLSEnabled:        cfg.Redis.TLSEnabled,
			TLSInsecureVerify: cfg.Redis.TLSInsecureVerify,
		}, mgr, logger)
	})
}

func initializeMemoryCache(mgr *cache.TTLMapManager) {
	mgr.CreateTTLMap(cache.GatewayTTLName, cache.GatewayCacheTTL)
	mgr.CreateTTLMap(cache.RegistryTTLName, cache.RegistryCacheTTL)
	mgr.CreateTTLMap(cache.ConsumerTTLName, cache.ConsumerCacheTTL)
	mgr.CreateTTLMap(cache.ConsumerDataTTLName, cache.ConsumerDataCacheTTL)
	mgr.CreateTTLMap(cache.PolicyTTLName, cache.PolicyCacheTTL)
	mgr.CreateTTLMap(cache.AuthTTLName, cache.AuthCacheTTL)
	mgr.CreateTTLMap(cache.AuthKeyTTLName, cache.AuthKeyCacheTTL)
	mgr.CreateTTLMap(cache.CatalogModelTTLName, cache.CatalogModelCacheTTL)
	mgr.CreateTTLMap(cache.MCPToolsTTLName, cache.MCPToolsCacheTTL)

	lbMap := mgr.CreateTTLMap(cache.LoadBalancerTTLName, cache.LoadBalancerCacheTTL)
	// Cached load balancers own a background goroutine; close it when the entry
	// is evicted (invalidation, replacement or TTL expiry) so it cannot leak.
	lbMap.SetOnEvict(func(value any) {
		if lb, ok := value.(*loadbalancer.LoadBalancer); ok {
			lb.Close()
		}
	})
}
