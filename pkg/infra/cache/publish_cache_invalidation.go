package cache

import (
	"context"
	"encoding/json"
	"fmt"

	redisCache "github.com/NeuralTrust/TrustGate/pkg/cache"
)

type InvalidationPublisher interface {
	Publish(ctx context.Context, gatewayID string) error
}

type invalidationPublisher struct {
	cache *redisCache.Cache
}

func NewInvalidationPublisher(cache *redisCache.Cache) InvalidationPublisher {
	return &invalidationPublisher{
		cache: cache,
	}
}

func (s *invalidationPublisher) Publish(ctx context.Context, gatewayID string) error {
	msg := map[string]string{
		"type":      "cache_invalidation",
		"gatewayID": gatewayID,
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	rdb := s.cache.Client()
	return rdb.Publish(ctx, "gateway_events", string(msgJSON)).Err()
}
