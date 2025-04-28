package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
)

const (
	EmbeddingCacheKeyPattern = "embedding:%s"
	EmbeddingCacheTTL        = 24 * time.Hour
)

type redisEmbeddingRepository struct {
	cache *cache.Cache
}

func NewRedisEmbeddingRepository(cache *cache.Cache) embedding.Repository {
	return &redisEmbeddingRepository{
		cache: cache,
	}
}

func (r *redisEmbeddingRepository) Store(
	ctx context.Context,
	targetID string,
	embeddingData *embedding.Embedding,
) error {
	embeddingData.EntityID = targetID
	key := fmt.Sprintf(EmbeddingCacheKeyPattern, targetID)
	jsonData, err := json.Marshal(embeddingData)
	if err != nil {
		return fmt.Errorf("failed to marshal embedding data: %w", err)
	}
	return r.cache.Set(ctx, key, string(jsonData), EmbeddingCacheTTL)
}

func (r *redisEmbeddingRepository) GetByTargetID(
	ctx context.Context,
	targetID string,
) (*embedding.Embedding, error) {
	key := fmt.Sprintf(EmbeddingCacheKeyPattern, targetID)

	jsonData, err := r.cache.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get embedding from cache: %w", err)
	}

	var data embedding.Embedding
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal embedding data: %w", err)
	}

	return &data, nil
}
