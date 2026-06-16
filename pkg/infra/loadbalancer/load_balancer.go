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

package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/go-redis/redis/v8"
)

type Pool struct {
	ID              string
	Registries      []*registry.Registry
	Weights         map[ids.RegistryID]int
	Algorithm       string
	EmbeddingConfig *registry.EmbeddingConfig
}

type LoadBalancer struct {
	strategy  Strategy
	logger    *slog.Logger
	cache     cache.Client
	poolID    string
	poolSize  int
	successCh chan *registry.Registry
	factory   Factory
	done      chan struct{}
	closeOnce sync.Once
}

func NewLoadBalancer(
	factory Factory,
	pool Pool,
	logger *slog.Logger,
	cacheClient cache.Client,
) (*LoadBalancer, error) {
	ctx := context.Background()

	seedInitialHealth(ctx, cacheClient, pool.Registries, logger)

	var embeddingCfg *embedding.Config
	if pool.EmbeddingConfig != nil {
		embeddingCfg = backendEmbeddingToDomain(pool.EmbeddingConfig)
	}

	strategy, err := factory.CreateStrategy(StrategyInput{
		Algorithm:       pool.Algorithm,
		Registries:      pool.Registries,
		Weights:         pool.Weights,
		EmbeddingConfig: embeddingCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancing strategy: %w", err)
	}

	lb := &LoadBalancer{
		strategy:  strategy,
		logger:    logger,
		cache:     cacheClient,
		poolID:    pool.ID,
		poolSize:  len(pool.Registries),
		successCh: make(chan *registry.Registry, 1000),
		factory:   factory,
		done:      make(chan struct{}),
	}
	go lb.processSuccessReports()
	return lb, nil
}

func healthKey(backendID string) string {
	return fmt.Sprintf("lb:health:%s", backendID)
}

func seedInitialHealth(
	ctx context.Context,
	cacheClient cache.Client,
	registries []*registry.Registry,
	logger *slog.Logger,
) {
	redisClient := cacheClient.RedisClient()
	if redisClient == nil {
		return
	}
	now := time.Now()
	for _, b := range registries {
		key := healthKey(b.ID.String())
		if exists, err := redisClient.Exists(ctx, key).Result(); err == nil && exists > 0 {
			continue
		}
		status := &HealthStatus{Healthy: true, LastCheck: now}
		statusJSON, err := json.Marshal(status)
		if err != nil {
			logger.Warn("failed to marshal health status for cache", slog.Any("error", err))
			continue
		}
		_ = redisClient.Set(ctx, key, statusJSON, time.Hour).Err()
	}
}

func (lb *LoadBalancer) processSuccessReports() {
	for {
		select {
		case b := <-lb.successCh:
			lb.performSuccessUpdate(b)
		case <-lb.done:
			return
		}
	}
}

func (lb *LoadBalancer) Close() {
	lb.closeOnce.Do(func() { close(lb.done) })
}

func (lb *LoadBalancer) ReportSuccess(b *registry.Registry) {
	select {
	case lb.successCh <- b:
	default:
	}
}

func (lb *LoadBalancer) performSuccessUpdate(b *registry.Registry) {
	ctx := context.Background()
	key := healthKey(b.ID.String())
	redisClient := lb.cache.RedisClient()
	if redisClient == nil {
		return
	}
	pipe := redisClient.Pipeline()
	status := HealthStatus{
		Healthy:   true,
		LastCheck: time.Now(),
		LastError: nil,
		Failures:  0,
	}
	statusJSON, _ := json.Marshal(status)
	pipe.Set(ctx, key, statusJSON, time.Hour)
	_, _ = pipe.Exec(ctx)
}

func (lb *LoadBalancer) NextBackend(
	req *infracontext.RequestContext,
	exclude map[ids.RegistryID]struct{},
) (*registry.Registry, error) {
	attempts := lb.poolSize
	if attempts < 1 {
		attempts = 1
	}
	var last *registry.Registry
	for i := 0; i < attempts; i++ {
		b := lb.strategy.Next(req, exclude)
		if b == nil {
			break
		}
		last = b
		if healthy, err := lb.isBackendHealthy(req, b.ID.String()); err == nil && healthy {
			return b, nil
		}
	}
	if last != nil {
		lb.logger.Info("all registries unhealthy; using last candidate as fallback",
			slog.String("registry_id", last.ID.String()),
			slog.String("provider", last.Provider()),
		)
		return last, nil
	}
	return nil, fmt.Errorf("no available registries")
}

func (lb *LoadBalancer) isBackendHealthy(req *infracontext.RequestContext, backendID string) (bool, error) {
	redisClient := lb.cache.RedisClient()
	if redisClient == nil {
		return true, nil
	}
	ctx := context.Background()
	if req != nil && req.Context != nil {
		ctx = req.Context
	}
	val, err := redisClient.Get(ctx, healthKey(backendID)).Result()
	if err != nil {
		return true, nil
	}
	var status HealthStatus
	if err := json.Unmarshal([]byte(val), &status); err != nil {
		return true, nil
	}
	return status.Healthy, nil
}

func (lb *LoadBalancer) ReportFailure(b *registry.Registry, err error) {
	lb.UpdateBackendHealth(b, false, err)
}

func (lb *LoadBalancer) UpdateBackendHealth(b *registry.Registry, healthy bool, err error) {
	hc := b.HealthChecks()
	if hc == nil || !hc.Passive {
		return
	}
	ctx := context.Background()
	key := healthKey(b.ID.String())
	failuresKey := key + ":failures"
	redisClient := lb.cache.RedisClient()
	if redisClient == nil {
		return
	}

	if !healthy {
		failures, _ := redisClient.Incr(ctx, failuresKey).Result()
		if hc.Interval > 0 {
			redisClient.Expire(ctx, failuresKey, time.Duration(hc.Interval)*time.Second)
		}
		if failures >= int64(hc.Threshold) {
			status := HealthStatus{
				Healthy:   false,
				LastCheck: time.Now(),
				LastError: err,
				Failures:  int(failures),
			}
			if cacheErr := cacheHealthStatus(ctx, redisClient, key, &status); cacheErr != nil {
				lb.logger.Error("failed to cache health status", slog.Any("error", cacheErr))
			}
		}
	} else {
		redisClient.Del(ctx, failuresKey)
		status := HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
			LastError: nil,
			Failures:  0,
		}
		if cacheErr := cacheHealthStatus(ctx, redisClient, key, &status); cacheErr != nil {
			lb.logger.Error("failed to cache health status", slog.Any("error", cacheErr))
		}
	}
}

func cacheHealthStatus(ctx context.Context, redisClient *redis.Client, key string, status *HealthStatus) error {
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal health status: %w", err)
	}
	return redisClient.Set(ctx, key, statusJSON, time.Hour).Err()
}

func backendEmbeddingToDomain(c *registry.EmbeddingConfig) *embedding.Config {
	out := &embedding.Config{
		Provider: c.Provider,
		Model:    c.Model,
	}
	if c.Auth != nil {
		out.Credentials = embedding.Credentials{
			APIKey:      c.Auth.APIKey,
			HeaderName:  c.Auth.HeaderName,
			HeaderValue: c.Auth.HeaderValue,
		}
		if out.Credentials.APIKey == "" && out.Credentials.HeaderValue != "" {
			out.Credentials.APIKey = out.Credentials.HeaderValue
		}
	}
	return out
}
