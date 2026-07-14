// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modules

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
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
			Login:             cfg.Redis.Login,
			Host:              cfg.Redis.Host,
			Port:              cfg.Redis.Port,
			Username:          cfg.Redis.Username,
			Password:          cfg.Redis.Password,
			DB:                cfg.Redis.DB,
			TLSEnabled:        cfg.Redis.TLSEnabled,
			TLSInsecureVerify: cfg.Redis.TLSInsecureVerify,
			CacheName:         cfg.Redis.CacheName,
			AWSServerless:     cfg.Redis.AWSServerless,
		}, mgr, logger)
	})
}

func StartCacheJanitor(ctx context.Context, mgr *cache.TTLMapManager) {
	mgr.StartJanitor(ctx, cache.JanitorInterval)
}

func initializeMemoryCache(mgr *cache.TTLMapManager) {
	mgr.CreateTTLMap(cache.GatewayTTLName, cache.GatewayCacheTTL)
	mgr.CreateTTLMap(cache.RegistryTTLName, cache.RegistryCacheTTL)
	mgr.CreateTTLMap(cache.ConsumerTTLName, cache.ConsumerCacheTTL)
	mgr.CreateTTLMap(cache.RoleTTLName, cache.RoleCacheTTL)
	mgr.CreateTTLMap(cache.ConsumerDataTTLName, cache.ConsumerDataCacheTTL)
	mgr.CreateTTLMap(cache.PolicyTTLName, cache.PolicyCacheTTL)
	mgr.CreateTTLMap(cache.AuthTTLName, cache.AuthCacheTTL)
	mgr.CreateTTLMap(cache.AuthKeyTTLName, cache.AuthKeyCacheTTL)
	mgr.CreateTTLMap(cache.CatalogModelTTLName, cache.CatalogModelCacheTTL)
	mgr.CreateTTLMap(cache.MCPToolsTTLName, cache.MCPToolsCacheTTL)

	lbMap := mgr.CreateTTLMap(cache.LoadBalancerTTLName, cache.LoadBalancerCacheTTL)
	lbMap.SetOnEvict(func(value any) {
		if lb, ok := value.(*loadbalancer.LoadBalancer); ok {
			lb.Close()
		}
	})
}
