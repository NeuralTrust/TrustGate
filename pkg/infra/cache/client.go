// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/go-redis/redis/v8"
)

const (
	GatewayKeyPattern = "gateway:%s"
)

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=client_mock.go --case=underscore --with-expecter
type Client interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	RedisClient() *redis.Client
	CreateTTLMap(name string, ttl time.Duration) *TTLMap
	GetTTLMap(name string) *TTLMap

	GetGateway(ctx context.Context, id string) (*domain.Gateway, error)
	SaveGateway(ctx context.Context, gateway *domain.Gateway) error

	DeleteAllByGatewayID(ctx context.Context, gatewayID string) error
	InvalidateAll(ctx context.Context) error
	ClearAllTTLMaps()
}

type Config struct {
	Host              string
	Port              int
	Password          string // #nosec G117 -- Config field for Redis password
	DB                int
	TLSEnabled        bool
	TLSInsecureVerify bool
}

var _ Client = (*client)(nil)

type client struct {
	redisClient *redis.Client
	localCache  sync.Map
	ttlManager  *TTLMapManager
	logger      *slog.Logger
}

func NewClient(config Config, manager *TTLMapManager, logger *slog.Logger) (Client, error) {
	options := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	}
	if config.TLSEnabled {
		options.TLSConfig = &tls.Config{
			InsecureSkipVerify: config.TLSInsecureVerify, // #nosec G402 -- callers opt in via config
		}
	}
	redisClient := redis.NewClient(options)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Error("failed to connect to redis",
			slog.String("host", config.Host),
			slog.Int("port", config.Port),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Info("redis connected successfully",
		slog.String("host", config.Host),
		slog.Int("port", config.Port),
	)

	return &client{
		redisClient: redisClient,
		localCache:  sync.Map{},
		ttlManager:  manager,
		logger:      logger,
	}, nil
}

func (c *client) Get(ctx context.Context, key string) (string, error) {
	if value, ok := c.localCache.Load(key); ok {
		str, err := safeStringCast(value)
		if err != nil {
			return "", fmt.Errorf("cache value error: %w", err)
		}
		return str, nil
	}
	return c.redisClient.Get(ctx, key).Result()
}

func (c *client) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.redisClient.Set(ctx, key, value, expiration).Err(); err != nil {
		return err
	}
	c.localCache.Store(key, value)
	return nil
}

func (c *client) Delete(ctx context.Context, key string) error {
	if err := c.redisClient.Del(ctx, key).Err(); err != nil {
		return err
	}
	c.localCache.Delete(key)
	return nil
}

func (c *client) DeleteAllByGatewayID(ctx context.Context, gatewayID string) error {
	pattern := fmt.Sprintf("*%s*", gatewayID)
	var cursor uint64
	for {
		keys, nextCursor, err := c.redisClient.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("error scanning keys: %w", err)
		}
		if len(keys) > 0 {
			if err := c.redisClient.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("error deleting keys: %w", err)
			}
			for _, key := range keys {
				c.localCache.Delete(key)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (c *client) InvalidateAll(ctx context.Context) error {
	var cursor uint64
	for {
		keys, nextCursor, err := c.redisClient.Scan(ctx, cursor, "*", 100).Result()
		if err != nil {
			return fmt.Errorf("error scanning keys: %w", err)
		}
		if len(keys) > 0 {
			if err := c.redisClient.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("error deleting keys: %w", err)
			}
			for _, key := range keys {
				c.localCache.Delete(key)
			}
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (c *client) RedisClient() *redis.Client {
	return c.redisClient
}

func (c *client) CreateTTLMap(name string, ttl time.Duration) *TTLMap {
	return c.ttlManager.CreateTTLMap(name, ttl)
}

func (c *client) GetTTLMap(name string) *TTLMap {
	return c.ttlManager.GetTTLMap(name)
}

func (c *client) ClearAllTTLMaps() {
	c.ttlManager.ClearAllTTLMaps()
}

func (c *client) SaveGateway(ctx context.Context, gateway *domain.Gateway) error {
	key := fmt.Sprintf(GatewayKeyPattern, gateway.ID.String())
	payload, err := json.Marshal(gateway)
	if err != nil {
		return err
	}
	return c.Set(ctx, key, string(payload), 0)
}

func (c *client) GetGateway(ctx context.Context, id string) (*domain.Gateway, error) {
	key := fmt.Sprintf(GatewayKeyPattern, id)
	res, err := c.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	g := new(domain.Gateway)
	if err := json.Unmarshal([]byte(res), g); err != nil {
		return nil, err
	}
	return g, nil
}

func safeStringCast(value interface{}) (string, error) {
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type assertion to string")
	}
	return str, nil
}
