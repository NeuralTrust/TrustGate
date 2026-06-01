package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/go-redis/redis/v8"
)

// Pool is the set of backends a single consumer balances across, together with
// the chosen algorithm and (for semantic) the embedding config. ID is the owning
// consumer id, used to key the LB instance cache. Passive health gating is driven
// per backend via each Backend.HealthChecks.
type Pool struct {
	ID              string
	Backends        []*backend.Backend
	Algorithm       string
	EmbeddingConfig *backend.EmbeddingConfig
}

type LoadBalancer struct {
	strategy  Strategy
	logger    *slog.Logger
	cache     cache.Client
	poolID    string
	poolSize  int
	successCh chan *backend.Backend
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

	// Rehydrate health state from Redis (the cross-pod source of truth). Only
	// seed the initial healthy status for backends that have no persisted state,
	// so a backend marked unhealthy survives LB rebuilds and pod restarts instead
	// of being reset to healthy on every reconstruction.
	seedInitialHealth(ctx, cacheClient, pool.Backends, logger)

	var embeddingCfg *embedding.Config
	if pool.EmbeddingConfig != nil {
		embeddingCfg = backendEmbeddingToDomain(pool.EmbeddingConfig)
	}

	strategy, err := factory.CreateStrategy(StrategyInput{
		Algorithm:       pool.Algorithm,
		Backends:        pool.Backends,
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
		poolSize:  len(pool.Backends),
		successCh: make(chan *backend.Backend, 1000),
		factory:   factory,
		done:      make(chan struct{}),
	}
	go lb.processSuccessReports()
	return lb, nil
}

func healthKey(backendID string) string {
	return fmt.Sprintf("lb:health:%s", backendID)
}

// seedInitialHealth writes a healthy status to Redis for each backend that has
// none yet. It writes through the raw Redis client (not the local-cache path)
// so the health namespace stays consistent with the direct Redis reads/writes
// used by isBackendHealthy and UpdateBackendHealth.
func seedInitialHealth(
	ctx context.Context,
	cacheClient cache.Client,
	backends []*backend.Backend,
	logger *slog.Logger,
) {
	redisClient := cacheClient.RedisClient()
	if redisClient == nil {
		return
	}
	now := time.Now()
	for _, b := range backends {
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

// Close stops the background success-report goroutine. It is idempotent, and
// ReportSuccess stays safe afterwards since successCh is never closed.
func (lb *LoadBalancer) Close() {
	lb.closeOnce.Do(func() { close(lb.done) })
}

func (lb *LoadBalancer) ReportSuccess(b *backend.Backend) {
	select {
	case lb.successCh <- b:
	default:
	}
}

func (lb *LoadBalancer) performSuccessUpdate(b *backend.Backend) {
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

// NextBackend asks the strategy for a backend and skips ones currently marked
// unhealthy, trying up to one full pass over the pool. When every candidate is
// unhealthy it falls back to the last pick rather than failing the request, so a
// stale/incorrect health flag cannot black-hole all traffic.
func (lb *LoadBalancer) NextBackend(req *infracontext.RequestContext) (*backend.Backend, error) {
	attempts := lb.poolSize
	if attempts < 1 {
		attempts = 1
	}
	var last *backend.Backend
	for i := 0; i < attempts; i++ {
		b := lb.strategy.Next(req)
		if b == nil {
			break
		}
		last = b
		if healthy, err := lb.isBackendHealthy(req, b.ID.String()); err == nil && healthy {
			return b, nil
		}
	}
	if last != nil {
		lb.logger.Info("all backends unhealthy; using last candidate as fallback",
			slog.String("backend_id", last.ID.String()),
			slog.String("provider", last.Provider),
		)
		return last, nil
	}
	return nil, fmt.Errorf("no available backends")
}

// isBackendHealthy reads the backend's health flag directly from Redis (the
// source of truth that UpdateBackendHealth writes to). It deliberately bypasses
// the local cache so a passive-health update is never shadowed by a stale local
// copy. An unreachable/missing/corrupt entry is treated as healthy (fail open).
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

func (lb *LoadBalancer) ReportFailure(b *backend.Backend, err error) {
	lb.UpdateBackendHealth(b, false, err)
}

func (lb *LoadBalancer) UpdateBackendHealth(b *backend.Backend, healthy bool, err error) {
	if b.HealthChecks == nil || !b.HealthChecks.Passive {
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
		if b.HealthChecks.Interval > 0 {
			redisClient.Expire(ctx, failuresKey, time.Duration(b.HealthChecks.Interval)*time.Second)
		}
		if failures >= int64(b.HealthChecks.Threshold) {
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

func backendEmbeddingToDomain(c *backend.EmbeddingConfig) *embedding.Config {
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
