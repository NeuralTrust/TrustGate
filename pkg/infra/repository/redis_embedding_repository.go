package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

const (
	EmbeddingCacheKeyPattern = "embedding:%s"
	EmbeddingCacheTTL        = 24 * time.Hour
)

type redisEmbeddingRepository struct {
	cache cache.Client
}

func NewRedisEmbeddingRepository(cache cache.Client) embedding.Repository {
	return &redisEmbeddingRepository{
		cache: cache,
	}
}

func (r *redisEmbeddingRepository) Store(
	ctx context.Context,
	targetID string,
	embeddingData *embedding.Embedding,
	key string,
) error {
	embeddingData.EntityID = targetID
	if key == "" {
		key = fmt.Sprintf(EmbeddingCacheKeyPattern, targetID)
	}
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

func (r *redisEmbeddingRepository) Count(ctx context.Context, index, gatewayID string) (int, error) {
	query := fmt.Sprintf("@gateway_id:{%s}", r.hashGatewayID(gatewayID))

	resp, err := r.cache.RedisClient().Do(ctx, "FT.SEARCH", index, query, "NOCONTENT").Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count keys for gateway ID %s: %w", gatewayID, err)
	}

	results, ok := resp.([]interface{})
	if !ok || len(results) == 0 {
		return 0, fmt.Errorf("unexpected response format from FT.SEARCH")
	}

	count, err := strconv.Atoi(fmt.Sprintf("%v", results[0]))
	if err != nil {
		return 0, fmt.Errorf("failed to parse count from FT.SEARCH response: %w", err)
	}

	return count, nil
}

func (r *redisEmbeddingRepository) StoreWithHMSet(
	ctx context.Context,
	index string,
	key string,
	gatewayID string,
	embedding *embedding.Embedding,
	data []byte,
) error {
	indexPrefix := index + ":"
	fullKey := indexPrefix + key

	blob, err := embedding.ToBlob()
	if err != nil {
		return fmt.Errorf("failed to convert embedding to blob: %w", err)
	}

	_, err = r.cache.RedisClient().HMSet(ctx, fullKey, map[string]interface{}{
		"embedding":  blob,
		"gateway_id": r.hashGatewayID(gatewayID),
		"data":       string(data),
	}).Result()

	if err != nil {
		return fmt.Errorf("failed to store embedding in Redis: %w", err)
	}

	return nil
}

func (r *redisEmbeddingRepository) Search(
	ctx context.Context,
	index, query string,
	emb *embedding.Embedding,
) ([]embedding.SearchResult, error) {
	blob, err := emb.ToBlob()
	if err != nil {
		return nil, fmt.Errorf("failed to convert embedding to blob: %w", err)
	}
	args := []interface{}{
		"FT.SEARCH", index,
		query,
		"PARAMS", "2", "BLOB", blob,
		"DIALECT", "2",
		"RETURN", "3", "data", "gateway_id", "score",
		"SORTBY", "score",
	}

	result := r.cache.RedisClient().Do(ctx, args...)
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("search error: %w", err)
	}

	resSlice, err := result.Slice()
	if err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	if len(resSlice) < 2 {
		return []embedding.SearchResult{}, nil
	}

	count, ok := resSlice[0].(int64)
	if !ok || count == 0 {
		return []embedding.SearchResult{}, nil
	}

	results := make([]embedding.SearchResult, 0, count)
	for i := 1; i < len(resSlice); i += 2 {
		key, ok := resSlice[i].(string)
		if !ok {
			continue
		}

		var data string
		var score float64

		if fields, ok := resSlice[i+1].([]interface{}); ok {
			for j := 0; j < len(fields); j += 2 {
				if j+1 < len(fields) {
					fieldName, fnOk := fields[j].(string)
					fieldValue, fvOk := fields[j+1].(string)
					if fnOk && fvOk {
						switch fieldName {
						case "data":
							data = fieldValue
						case "score":
							if scoreVal, err := strconv.ParseFloat(fieldValue, 64); err == nil {
								score = 1.0 - scoreVal
							}
						}
					}
				}
			}
		}

		results = append(results, embedding.SearchResult{
			Key:   key,
			Score: score,
			Data:  data,
		})
	}

	return results, nil
}

func (r *redisEmbeddingRepository) hashGatewayID(value string) string {
	h := sha256.New()
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
