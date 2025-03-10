package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"

	"github.com/go-redis/redis/v8"
)

func (c *Cache) GetAPIKeys(gatewayID string) ([]apikey.APIKey, error) {
	key := fmt.Sprintf("apikeys:%s", gatewayID)
	data, err := c.Client().Get(context.Background(), key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []apikey.APIKey{}, nil
		}
		return nil, err
	}

	var keys []apikey.APIKey
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return nil, err
	}

	return keys, nil
}

func (c *Cache) ValidateAPIKey(gatewayID, apiKey string) bool {
	key, err := c.GetAPIKey(gatewayID, apiKey)
	if err != nil {
		return false
	}

	if key == nil {
		return false
	}

	now := time.Now()
	return key.Active && (key.ExpiresAt.IsZero() || key.ExpiresAt.After(now))
}

func (c *Cache) GetAPIKey(gatewayID, apiKey string) (*apikey.APIKey, error) {
	// Get all API keys for the gateway
	keys, err := c.GetAPIKeys(gatewayID)
	if err != nil {
		return nil, err
	}

	// Find the matching key
	for _, key := range keys {
		if key.Key == apiKey {
			return &key, nil
		}
	}

	return nil, nil
}

func (c *Cache) SaveAPIKey(ctx context.Context, key *apikey.APIKey) error {
	// Get existing keys
	keys, err := c.GetAPIKeys(key.GatewayID)
	if err != nil {
		return err
	}

	// Add new key
	keys = append(keys, *key)

	// Save back to cache
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	cacheKey := fmt.Sprintf("apikeys:%s", key.GatewayID)
	return c.Client().Set(ctx, cacheKey, string(data), 0).Err()
}
