package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type LoadBalancer struct {
	strategy     Strategy
	logger       *logrus.Logger
	cache        *cache.Cache
	upstreamID   string
	upstream     *upstream.Upstream
	targetStatus map[string]*TargetStatus
	successCh    chan *types.UpstreamTarget
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
	cache *cache.Cache,
) (*LoadBalancer, error) {
	targets := make([]types.UpstreamTarget, len(upstream.Targets))
	ctx := context.Background()
	cacheTTL := time.Hour
	now := time.Now()

	for i, t := range upstream.Targets {
		credentials := types.Credentials(t.Credentials)

		healthStatus := &types.HealthStatus{
			Healthy:   true,
			LastCheck: now,
		}

		key := fmt.Sprintf("lb:health:%s:%s", upstream.ID, t.ID)
		if statusJSON, err := json.Marshal(healthStatus); err == nil {
			_ = cache.Set(ctx, key, string(statusJSON), cacheTTL)
		} else {
			logger.WithError(err).Warn("Failed to marshal health status for cache")
		}
		targets[i] = types.UpstreamTarget{
			ID:           t.ID,
			Weight:       t.Weight,
			Priority:     t.Priority,
			Host:         t.Host,
			Port:         t.Port,
			Protocol:     t.Protocol,
			Provider:     t.Provider,
			Models:       t.Models,
			DefaultModel: t.DefaultModel,
			Credentials:  credentials,
			Headers:      t.Headers,
			Path:         t.Path,
			Health:       healthStatus,
		}
	}

	strategy, err := factory.CreateStrategy(upstream.Algorithm, targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancing strategy: %w", err)
	}

	lb := &LoadBalancer{
		strategy:     strategy,
		logger:       logger,
		cache:        cache,
		upstreamID:   upstream.ID,
		upstream:     upstream,
		targetStatus: make(map[string]*TargetStatus),
		successCh:    make(chan *types.UpstreamTarget, 1000),
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

func (lb *LoadBalancer) ReportSuccess(target *types.UpstreamTarget) {
	select {
	case lb.successCh <- target:
	default:
	}
}

func (lb *LoadBalancer) performSuccessUpdate(target *types.UpstreamTarget) {
	ctx := context.Background()
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	redisClient := lb.cache.Client()

	pipe := redisClient.Pipeline()

	status := types.HealthStatus{
		Healthy:   true,
		LastCheck: time.Now(),
		LastError: nil,
		Failures:  0,
	}

	statusJSON, _ := json.Marshal(status)
	pipe.Set(ctx, key, statusJSON, time.Hour)

	_, _ = pipe.Exec(ctx)
}

func (lb *LoadBalancer) NextTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	target := lb.strategy.Next(ctx)
	if target == nil {
		return nil, fmt.Errorf("no available targets")
	}
	health, err := lb.isTargetHealthy(ctx, target.ID)
	if err == nil && health {
		return target, nil
	}
	return lb.fallbackTarget(ctx)
}

func (lb *LoadBalancer) fallbackTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	target := lb.strategy.Next(ctx)
	if target != nil {
		lb.logger.WithFields(logrus.Fields{
			"target_id": target.ID,
			"provider":  target.Provider,
		}).Info("Using fallback target")
		return target, nil
	}
	return nil, fmt.Errorf("no targets available for fallback")
}

func (lb *LoadBalancer) isTargetHealthy(ctx context.Context, targetID string) (bool, error) {
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, targetID)
	val, err := lb.cache.Get(ctx, key)
	if err != nil {
		return false, err
	}
	return strings.Contains(val, `"Healthy":true`), nil
}

func (lb *LoadBalancer) ReportFailure(target *types.UpstreamTarget, err error) {
	lb.UpdateTargetHealth(target, false, err)
}

func (lb *LoadBalancer) UpdateTargetHealth(target *types.UpstreamTarget, healthy bool, err error) {
	if lb.upstream.HealthChecks == nil || !lb.upstream.HealthChecks.Passive {
		return
	}

	ctx := context.Background()
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	failuresKey := fmt.Sprintf("lb:health:%s:%s:failures", lb.upstreamID, target.ID)
	redisClient := lb.cache.Client()

	if !healthy {
		failures, _ := redisClient.Incr(ctx, failuresKey).Result()
		if lb.upstream.HealthChecks.Interval > 0 {
			redisClient.Expire(ctx, failuresKey, time.Duration(lb.upstream.HealthChecks.Interval)*time.Second)
		}

		if failures >= int64(lb.upstream.HealthChecks.Threshold) {
			status := types.HealthStatus{
				Healthy:   false,
				LastCheck: time.Now(),
				LastError: err,
				Failures:  int(failures),
			}

			if err := cacheHealthStatus(ctx, redisClient, key, &status); err != nil {
				lb.logger.WithError(err).Error("Failed to cache health status")
			}
		}
	} else {
		redisClient.Del(ctx, failuresKey)

		status := types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
			LastError: nil,
			Failures:  0,
		}

		if err := cacheHealthStatus(ctx, redisClient, key, &status); err != nil {
			lb.logger.WithError(err).Error("Failed to cache health status")
		}
	}
}

func cacheHealthStatus(ctx context.Context, redisClient *redis.Client, key string, status *types.HealthStatus) error {
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal health status: %w", err)
	}
	return redisClient.Set(ctx, key, statusJSON, time.Hour).Err()
}
