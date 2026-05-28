package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/go-redis/redis/v8"
)

type LoadBalancer struct {
	strategy     Strategy
	logger       *slog.Logger
	cache        cache.Client
	backendID    string
	backend      *backend.Backend
	targetStatus map[string]*TargetStatus
	successCh    chan *backend.Target
	factory      Factory
}

type TargetStatus struct {
	LastAccess time.Time
	Failures   int
	Healthy    bool
	LastError  error
}

func NewLoadBalancer(
	factory Factory,
	bk *backend.Backend,
	logger *slog.Logger,
	cacheClient cache.Client,
) (*LoadBalancer, error) {
	targets := make([]backend.Target, len(bk.Targets))
	copy(targets, bk.Targets)

	ctx := context.Background()
	cacheTTL := time.Hour
	now := time.Now()

	for i := range targets {
		status := &HealthStatus{Healthy: true, LastCheck: now}
		key := fmt.Sprintf("lb:health:%s:%s", bk.ID, targets[i].ID)
		if statusJSON, err := json.Marshal(status); err == nil {
			_ = cacheClient.Set(ctx, key, string(statusJSON), cacheTTL)
		} else {
			logger.Warn("failed to marshal health status for cache", slog.Any("error", err))
		}
	}

	var embeddingCfg *embedding.Config
	if bk.EmbeddingConfig != nil {
		embeddingCfg = backendEmbeddingToDomain(bk.EmbeddingConfig)
	}

	strategy, err := factory.CreateStrategy(StrategyInput{
		Algorithm:       bk.Algorithm,
		Targets:         targets,
		EmbeddingConfig: embeddingCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancing strategy: %w", err)
	}

	lb := &LoadBalancer{
		strategy:     strategy,
		logger:       logger,
		cache:        cacheClient,
		backendID:    bk.ID.String(),
		backend:      bk,
		targetStatus: make(map[string]*TargetStatus),
		successCh:    make(chan *backend.Target, 1000),
		factory:      factory,
	}
	go lb.processSuccessReports()
	return lb, nil
}

func (lb *LoadBalancer) processSuccessReports() {
	for target := range lb.successCh {
		lb.performSuccessUpdate(target)
	}
}

func (lb *LoadBalancer) ReportSuccess(target *backend.Target) {
	select {
	case lb.successCh <- target:
	default:
	}
}

func (lb *LoadBalancer) performSuccessUpdate(target *backend.Target) {
	ctx := context.Background()
	key := fmt.Sprintf("lb:health:%s:%s", lb.backendID, target.ID)
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

func (lb *LoadBalancer) NextTarget(req *infracontext.RequestContext) (*backend.Target, error) {
	target := lb.strategy.Next(req)
	if target == nil {
		return nil, fmt.Errorf("no available targets")
	}
	healthy, err := lb.isTargetHealthy(req, target.ID)
	if err == nil && healthy {
		return target, nil
	}
	return lb.fallbackTarget(req)
}

func (lb *LoadBalancer) fallbackTarget(req *infracontext.RequestContext) (*backend.Target, error) {
	target := lb.strategy.Next(req)
	if target != nil {
		lb.logger.Info("using fallback target",
			slog.String("target_id", target.ID),
			slog.String("provider", target.Provider),
		)
		return target, nil
	}
	return nil, fmt.Errorf("no targets available for fallback")
}

func (lb *LoadBalancer) isTargetHealthy(req *infracontext.RequestContext, targetID string) (bool, error) {
	ctx := context.Background()
	if req != nil && req.Context != nil {
		ctx = req.Context
	}
	key := fmt.Sprintf("lb:health:%s:%s", lb.backendID, targetID)
	val, err := lb.cache.Get(ctx, key)
	if err != nil {
		return true, nil
	}
	var status HealthStatus
	if err := json.Unmarshal([]byte(val), &status); err != nil {
		return true, nil
	}
	return status.Healthy, nil
}

func (lb *LoadBalancer) ReportFailure(target *backend.Target, err error) {
	lb.UpdateTargetHealth(target, false, err)
}

func (lb *LoadBalancer) UpdateTargetHealth(target *backend.Target, healthy bool, err error) {
	if lb.backend.HealthChecks == nil || !lb.backend.HealthChecks.Passive {
		return
	}
	ctx := context.Background()
	key := fmt.Sprintf("lb:health:%s:%s", lb.backendID, target.ID)
	failuresKey := fmt.Sprintf("lb:health:%s:%s:failures", lb.backendID, target.ID)
	redisClient := lb.cache.RedisClient()
	if redisClient == nil {
		return
	}

	if !healthy {
		failures, _ := redisClient.Incr(ctx, failuresKey).Result()
		if lb.backend.HealthChecks.Interval > 0 {
			redisClient.Expire(ctx, failuresKey, time.Duration(lb.backend.HealthChecks.Interval)*time.Second)
		}
		if failures >= int64(lb.backend.HealthChecks.Threshold) {
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
