package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/types"

	"github.com/sirupsen/logrus"
)

type LoadBalancer struct {
	mu           sync.RWMutex
	strategy     Strategy
	logger       *logrus.Logger
	cache        *cache.Cache
	upstreamID   string
	upstream     *models.Upstream
	targetStatus map[string]*TargetStatus
}

type TargetStatus struct {
	LastAccess time.Time
	Failures   int
	Healthy    bool
	LastError  error
}

func NewLoadBalancer(upstream *models.Upstream, logger *logrus.Logger, cache *cache.Cache) (*LoadBalancer, error) {
	// Convert upstream targets to UpstreamTarget type
	targets := make([]types.UpstreamTarget, len(upstream.Targets))
	for i, t := range upstream.Targets {
		var creds types.Credentials
		if credBytes, err := json.Marshal(t.Credentials); err == nil {
			if err := json.Unmarshal(credBytes, &creds); err != nil {
				log.Printf("Failed to unmarshal credentials: %v", err)
			}
		}

		// Initialize health status
		healthStatus := &types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
		}

		// Store initial health status in cache
		key := fmt.Sprintf("lb:health:%s:%s", upstream.ID, t.ID)
		if statusJSON, err := json.Marshal(healthStatus); err == nil {
			if err := cache.Set(context.Background(), key, string(statusJSON), time.Hour); err != nil {
				return nil, fmt.Errorf("failed to set cache: %w", err)
			}
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
			Credentials:  creds,
			Headers:      t.Headers,
			Path:         t.Path,
			Health:       healthStatus,
		}
	}

	// Create the base factory
	factory := NewBaseFactory()

	// Create strategy based on algorithm
	strategy, err := factory.CreateStrategy(upstream.Algorithm, targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancing strategy: %w", err)
	}

	return &LoadBalancer{
		strategy:     strategy,
		logger:       logger,
		cache:        cache,
		upstreamID:   upstream.ID,
		upstream:     upstream,
		targetStatus: make(map[string]*TargetStatus),
	}, nil
}

func (lb *LoadBalancer) NextTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	target := lb.strategy.Next()
	if target == nil {
		return nil, fmt.Errorf("no available targets")
	}

	health, err := lb.isTargetHealthy(ctx, target.ID)
	if err == nil && health {
		return target, nil
	}

	// If target is unhealthy, try to get another one
	return lb.fallbackTarget(ctx)
}

// UpdateTargetHealth updates the target's health status
func (lb *LoadBalancer) UpdateTargetHealth(target *types.UpstreamTarget, healthy bool, err error) {
	if lb.upstream.HealthChecks == nil || !lb.upstream.HealthChecks.Passive {
		return
	}

	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	failuresKey := fmt.Sprintf("lb:health:%s:%s:failures", lb.upstreamID, target.ID)

	if !healthy {
		failures, _ := lb.cache.Client().Incr(context.Background(), failuresKey).Result()

		if lb.upstream.HealthChecks.Interval > 0 {
			lb.cache.Client().Expire(context.Background(), failuresKey,
				time.Duration(lb.upstream.HealthChecks.Interval)*time.Second)
		}

		if failures >= int64(lb.upstream.HealthChecks.Threshold) {
			status := &types.HealthStatus{
				Healthy:   false,
				LastCheck: time.Now(),
				LastError: err,
				Failures:  int(failures),
			}
			statusJSON, err := json.Marshal(status)
			if err != nil {
				lb.logger.WithError(err).Error("Failed to marshal health status")
				return
			}
			if err := lb.cache.Set(context.Background(), key, string(statusJSON), time.Hour); err != nil {
				lb.logger.WithError(err).Error("Failed to cache health status")
			}
		}
	} else {
		if err := lb.cache.Delete(context.Background(), failuresKey); err != nil {
			lb.logger.WithError(err).Error("Failed to delete failures key")
		}

		status := &types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
			LastError: nil,
			Failures:  0,
		}
		statusJSON, err := json.Marshal(status)
		if err != nil {
			lb.logger.WithError(err).Error("Failed to marshal health status")
			return
		}
		if err := lb.cache.Set(context.Background(), key, string(statusJSON), time.Hour); err != nil {
			lb.logger.WithError(err).Error("Failed to cache health status")
		}
	}
}

func (lb *LoadBalancer) ReportSuccess(target *types.UpstreamTarget) {
	lb.UpdateTargetHealth(target, true, nil)
}

func (lb *LoadBalancer) ReportFailure(target *types.UpstreamTarget, err error) {
	lb.UpdateTargetHealth(target, false, err)
}

// Add the helper methods for health checks
func (lb *LoadBalancer) getTargetHealth(ctx context.Context, targetID string) (*types.HealthStatus, error) {
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, targetID)
	val, err := lb.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	var health types.HealthStatus
	if err := json.Unmarshal([]byte(val), &health); err != nil {
		return nil, err
	}

	return &health, nil
}

func (lb *LoadBalancer) isTargetHealthy(ctx context.Context, targetID string) (bool, error) {
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, targetID)
	val, err := lb.cache.Get(ctx, key)
	needle := `"Healthy":true`
	if err != nil {
		return false, err
	}
	return strings.Contains(val, needle), nil
}

func (lb *LoadBalancer) fallbackTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	target := lb.strategy.Next()
	if target != nil {
		lb.logger.WithFields(logrus.Fields{
			"target_id": target.ID,
			"provider":  target.Provider,
		}).Info("Using fallback target")
		return target, nil
	}
	return nil, fmt.Errorf("no targets available for fallback")
}
