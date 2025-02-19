package gateway

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type InvalidateGatewayCache interface {
	Invalidate(ctx context.Context, gatewayID string) error
}

type invalidateGatewayCache struct {
	cache     *cache.Cache
	publisher infraCache.InvalidationPublisher
}

func NewInvalidateGatewayCache(cache *cache.Cache, publisher infraCache.InvalidationPublisher) InvalidateGatewayCache {
	return &invalidateGatewayCache{
		cache:     cache,
		publisher: publisher,
	}
}

func (s *invalidateGatewayCache) Invalidate(ctx context.Context, gatewayID string) error {
	// Get cache keys
	keys := common.GetCacheKeys(gatewayID)

	// Delete cache entries and handle errors
	if err := s.cache.Delete(ctx, keys.Gateway); err != nil {
		return fmt.Errorf("failed to delete gateway cache: %w", err)
	}

	if err := s.cache.Delete(ctx, keys.Rules); err != nil {
		return fmt.Errorf("failed to delete rules cache: %w", err)
	}

	if err := s.cache.Delete(ctx, keys.Plugin); err != nil {
		return fmt.Errorf("failed to delete plugin cache: %w", err)
	}

	// Publish cache invalidation event
	if err := s.publisher.Publish(ctx, gatewayID); err != nil {
		return fmt.Errorf("failed to publish cache invalidation: %w", err)
	}

	return nil
}
