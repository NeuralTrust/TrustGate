package modules

import (
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

// Cache wires the in-process TTL cache singleton. RUN-291 (B.1) will
// add a Redis client provider alongside this manager — finders consume
// both through their existing constructor and the manager keeps
// handing out per-namespace TTLMaps.
func Cache(c *container.Container) error {
	return c.Provide(func(cfg *config.Config) *cache.TTLMapManager {
		return cache.NewTTLMapManager(cfg.Cache.LocalTTL)
	})
}
