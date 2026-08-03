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
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/redis/go-redis/v9"
)

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=client_mock.go --case=underscore --with-expecter
type Client interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	RedisClient() *redis.Client
	CreateTTLMap(name string, ttl time.Duration) *TTLMap
	GetTTLMap(name string) *TTLMap
	ClearAllTTLMaps()
}

type Config struct {
	Login             string
	Host              string
	Port              int
	Password          string // #nosec G117 -- Config field for Redis password
	DB                int
	TLSEnabled        bool
	TLSInsecureVerify bool
	Username          string
	CacheName         string
	AWSServerless     bool
}

var _ Client = (*client)(nil)

type client struct {
	redisClient *redis.Client
	localCache  sync.Map
	ttlManager  *TTLMapManager
	logger      *slog.Logger
}

func buildRedisOptions(config Config, provider credentialsProvider) *redis.Options {
	options := &redis.Options{
		Addr: fmt.Sprintf("%s:%d", config.Host, config.Port),
		DB:   config.DB,
	}
	if provider == nil {
		options.Username = config.Username
		options.Password = config.Password
		if config.TLSEnabled {
			options.TLSConfig = &tls.Config{
				InsecureSkipVerify: config.TLSInsecureVerify, // #nosec G402 -- callers opt in via config
			}
		}
		return options
	}
	options.Username = config.Username
	options.Password = ""
	options.CredentialsProviderContext = provider
	options.TLSConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: config.TLSInsecureVerify, // #nosec G402 -- callers opt in via config
	}
	return options
}

func NewClient(config Config, manager *TTLMapManager, logger *slog.Logger) (Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider, err := newCredentialsProvider(ctx, &config, defaultRedisAuthDependencies())
	if err != nil {
		return nil, fmt.Errorf("configure redis authentication: %w", err)
	}

	options := buildRedisOptions(config, provider)
	redisClient := redis.NewClient(options)

	if err := redisClient.Ping(ctx).Err(); err != nil {
		logger.Error("failed to connect to redis",
			slog.String("host", config.Host),
			slog.Int("port", config.Port),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Info(bootlog.RedisConnected,
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

func safeStringCast(value any) (string, error) {
	str, ok := value.(string)
	if !ok {
		return "", errors.New("invalid type assertion to string")
	}
	return str, nil
}
