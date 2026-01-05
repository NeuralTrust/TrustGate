package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type LoadBalancer struct {
	strategy     Strategy
	logger       *logrus.Logger
	cache        cache.Client
	upstreamID   string
	upstream     *upstream.Upstream
	targetStatus map[string]*TargetStatus
	successCh    chan *types.UpstreamTargetDTO
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
	upstream *upstream.Upstream,
	logger *logrus.Logger,
	cache cache.Client,
) (*LoadBalancer, error) {
	targets := make([]types.UpstreamTargetDTO, len(upstream.Targets))
	ctx := context.Background()
	cacheTTL := time.Hour
	now := time.Now()

	var embeddingConfig *types.EmbeddingConfigDTO

	for i, t := range upstream.Targets {
		creds := t.Credentials

		healthStatus := &types.HealthStatusDTO{
			Healthy:   true,
			LastCheck: now,
		}

		key := fmt.Sprintf("lb:health:%s:%s", upstream.ID, t.ID)
		if statusJSON, err := json.Marshal(healthStatus); err == nil {
			_ = cache.Set(ctx, key, string(statusJSON), cacheTTL)
		} else {
			logger.WithError(err).Warn("Failed to marshal health status for cache")
		}
		targets[i] = types.UpstreamTargetDTO{
			ID:              t.ID,
			Weight:          t.Weight,
			Host:            t.Host,
			Port:            t.Port,
			Protocol:        t.Protocol,
			Provider:        t.Provider,
			ProviderOptions: t.ProviderOptions,
			Models:          t.Models,
			DefaultModel:    t.DefaultModel,
			Description:     t.Description,
			Credentials:     creds,
			Headers:         t.Headers,
			Path:            t.Path,
			Health:          healthStatus,
			Stream:          t.Stream,
			InsecureSSL:     t.InsecureSSL,
		}
	}
	if upstream.EmbeddingConfig != nil {
		embeddingConfig = &types.EmbeddingConfigDTO{
			Provider:    upstream.EmbeddingConfig.Provider,
			Model:       upstream.EmbeddingConfig.Model,
			Credentials: upstream.EmbeddingConfig.Credentials,
		}
	}
	strategy, err := factory.CreateStrategy(
		&types.UpstreamDTO{
			Algorithm:       upstream.Algorithm,
			EmbeddingConfig: embeddingConfig,
			Targets:         targets,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancing strategy: %w", err)
	}

	lb := &LoadBalancer{
		strategy:     strategy,
		logger:       logger,
		cache:        cache,
		upstreamID:   upstream.ID.String(),
		upstream:     upstream,
		targetStatus: make(map[string]*TargetStatus),
		successCh:    make(chan *types.UpstreamTargetDTO, 1000),
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

func (lb *LoadBalancer) ReportSuccess(target *types.UpstreamTargetDTO) {
	select {
	case lb.successCh <- target:
	default:
	}
}

func (lb *LoadBalancer) performSuccessUpdate(target *types.UpstreamTargetDTO) {
	ctx := context.Background()
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	redisClient := lb.cache.RedisClient()

	pipe := redisClient.Pipeline()

	status := types.HealthStatusDTO{
		Healthy:   true,
		LastCheck: time.Now(),
		LastError: nil,
		Failures:  0,
	}

	statusJSON, _ := json.Marshal(status)
	pipe.Set(ctx, key, statusJSON, time.Hour)

	_, _ = pipe.Exec(ctx)
}

func (lb *LoadBalancer) NextTarget(req *types.RequestContext) (*types.UpstreamTargetDTO, error) {
	target := lb.strategy.Next(req)
	if target == nil {
		return nil, fmt.Errorf("no available targets")
	}
	health, err := lb.isTargetHealthy(req, target.ID)
	if err == nil && health {
		return target, nil
	}
	return lb.fallbackTarget(req)
}

func (lb *LoadBalancer) fallbackTarget(req *types.RequestContext) (*types.UpstreamTargetDTO, error) {
	target := lb.strategy.Next(req)
	if target != nil {
		lb.logger.WithFields(logrus.Fields{
			"target_id": target.ID,
			"provider":  target.Provider,
		}).Info("Using fallback target")
		return target, nil
	}
	return nil, fmt.Errorf("no targets available for fallback")
}

func (lb *LoadBalancer) isTargetHealthy(req *types.RequestContext, targetID string) (bool, error) {
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, targetID)
	val, err := lb.cache.Get(req.Context, key)
	if err != nil {
		return true, nil
	}
	var status types.HealthStatusDTO
	if err := json.Unmarshal([]byte(val), &status); err != nil {
		return true, nil
	}
	return status.Healthy, nil
}

func (lb *LoadBalancer) ReportFailure(target *types.UpstreamTargetDTO, err error) {
	lb.UpdateTargetHealth(target, false, err)
}

func (lb *LoadBalancer) UpdateTargetHealth(target *types.UpstreamTargetDTO, healthy bool, err error) {
	if lb.upstream.HealthChecks == nil || !lb.upstream.HealthChecks.Passive {
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	failuresKey := fmt.Sprintf("lb:health:%s:%s:failures", lb.upstreamID, target.ID)
	redisClient := lb.cache.RedisClient()

	if !healthy {
		failures, _ := redisClient.Incr(ctx, failuresKey).Result()
		if lb.upstream.HealthChecks.Interval > 0 {
			redisClient.Expire(ctx, failuresKey, time.Duration(lb.upstream.HealthChecks.Interval)*time.Second)
		}

		if failures >= int64(lb.upstream.HealthChecks.Threshold) {
			status := types.HealthStatusDTO{
				Healthy:   false,
				LastCheck: time.Now(),
				LastError: err,
				Failures:  int(failures),
			}

			if ok := cacheHealthStatus(ctx, redisClient, key, &status); ok != nil {
				lb.logger.WithError(ok).Error("Failed to cache health status")
			}
		}
	} else {
		redisClient.Del(ctx, failuresKey)

		status := types.HealthStatusDTO{
			Healthy:   true,
			LastCheck: time.Now(),
			LastError: nil,
			Failures:  0,
		}

		if ok := cacheHealthStatus(ctx, redisClient, key, &status); ok != nil {
			lb.logger.WithError(ok).Error("Failed to cache health status")
		}
	}
}

func cacheHealthStatus(ctx context.Context, redisClient *redis.Client, key string, status *types.HealthStatusDTO) error {
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal health status: %w", err)
	}
	return redisClient.Set(ctx, key, statusJSON, time.Hour).Err()
}
