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

package proxy

import (
	"fmt"
	"log/slog"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"golang.org/x/sync/singleflight"
)

// loadBalancerCache builds and memoizes per-consumer load balancers. It owns
// the singleflight group and TTL cache so a burst of concurrent requests for
// the same consumer collapses into a single balancer build.
type loadBalancerCache struct {
	factory loadbalancer.Factory
	redis   loadbalancer.RedisProvider
	ttl     *cache.TTLMap
	group   singleflight.Group
	logger  *slog.Logger
}

func newLoadBalancerCache(
	factory loadbalancer.Factory,
	redis loadbalancer.RedisProvider,
	ttl *cache.TTLMap,
	logger *slog.Logger,
) *loadBalancerCache {
	return &loadBalancerCache{
		factory: factory,
		redis:   redis,
		ttl:     ttl,
		logger:  logger,
	}
}

func (c *loadBalancerCache) For(rc *appconsumer.RoutableConsumer) (*loadbalancer.LoadBalancer, error) {
	key := loadBalancerCacheKey(rc.Consumer.GatewayID, rc.Consumer.ID)
	return c.getOrBuild(key, func() loadbalancer.Pool {
		lbAlgorithm, embeddingConfig := lbSettings(rc)
		return loadbalancer.Pool{
			ID:              key,
			Registries:      rc.Registries,
			Weights:         rc.Consumer.RegistryWeights,
			Algorithm:       lbAlgorithm,
			EmbeddingConfig: embeddingConfig,
		}
	})
}

func (c *loadBalancerCache) PoolFor(
	rc *appconsumer.RoutableConsumer,
	alias string,
	candidates *routingdomain.CandidateSet,
) (*loadbalancer.LoadBalancer, error) {
	key := poolLoadBalancerCacheKey(rc.Consumer.GatewayID, rc.Consumer.ID, alias)
	return c.getOrBuild(key, func() loadbalancer.Pool {
		lbAlgorithm, embeddingConfig := lbSettings(rc)
		return loadbalancer.Pool{
			ID:              key,
			Registries:      candidates.Registries(),
			Weights:         rc.Consumer.RegistryWeights,
			Algorithm:       lbAlgorithm,
			EmbeddingConfig: embeddingConfig,
		}
	})
}

func (c *loadBalancerCache) getOrBuild(
	key string,
	buildPool func() loadbalancer.Pool,
) (*loadbalancer.LoadBalancer, error) {
	if lb, ok := c.cached(key); ok {
		return lb, nil
	}
	built, err, _ := c.group.Do(key, func() (any, error) {
		if lb, ok := c.cached(key); ok {
			return lb, nil
		}
		lb, err := loadbalancer.NewLoadBalancer(c.factory, buildPool(), c.logger, c.redis)
		if err != nil {
			return nil, err
		}
		c.ttl.Set(key, lb)
		return lb, nil
	})
	if err != nil {
		return nil, err
	}
	lb, ok := built.(*loadbalancer.LoadBalancer)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected load balancer type %T", ErrNoBackendAvailable, built)
	}
	return lb, nil
}

func (c *loadBalancerCache) cached(key string) (*loadbalancer.LoadBalancer, bool) {
	cached, ok := c.ttl.Get(key)
	if !ok {
		return nil, false
	}
	lb, ok := cached.(*loadbalancer.LoadBalancer)
	if !ok {
		c.logger.Warn("load balancer cache entry failed type assertion; rebuilding",
			slog.String("lb_key", key))
		c.ttl.Delete(key)
		return nil, false
	}
	return lb, true
}

func lbSettings(rc *appconsumer.RoutableConsumer) (string, *domain.EmbeddingConfig) {
	lbAlgorithm := algorithm.RoundRobin
	var embeddingConfig *domain.EmbeddingConfig
	if lbCfg := rc.Consumer.LBConfig; lbCfg != nil && lbCfg.Enabled {
		if lbCfg.Algorithm != "" {
			lbAlgorithm = lbCfg.Algorithm
		}
		embeddingConfig = lbCfg.EmbeddingConfig
	}
	return lbAlgorithm, embeddingConfig
}

func loadBalancerCacheKey(gatewayID ids.GatewayID, consumerID ids.ConsumerID) string {
	return gatewayID.String() + ":" + consumerID.String()
}

func poolLoadBalancerCacheKey(gatewayID ids.GatewayID, consumerID ids.ConsumerID, alias string) string {
	return gatewayID.String() + ":" + consumerID.String() + ":pool:" + strings.ToLower(alias)
}
