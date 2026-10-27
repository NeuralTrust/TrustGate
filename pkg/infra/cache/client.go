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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	RedisClient() redis.UniversalClient
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
	// Cluster builds a Redis Cluster client seeded with Host:Port.
	Cluster bool
	// TLSCAFile is a PEM bundle used as the root CAs that verify the server.
	TLSCAFile string
}

var _ Client = (*client)(nil)

type client struct {
	redisClient redis.UniversalClient
	localCache  sync.Map
	ttlManager  *TTLMapManager
	logger      *slog.Logger
}

var errRedisTLSCAInsecure = errors.New("a redis TLS CA file cannot be combined with insecure verification")

func buildRedisOptions(config Config, provider credentialsProvider) (*redis.Options, error) {
	options := &redis.Options{
		Addr: fmt.Sprintf("%s:%d", config.Host, config.Port),
		DB:   config.DB,
	}
	options.Username = config.Username
	if provider == nil {
		options.Password = config.Password
		if config.TLSEnabled {
			tlsConfig, err := buildTLSConfig(config, 0)
			if err != nil {
				return nil, err
			}
			options.TLSConfig = tlsConfig
		}
		return options, nil
	}
	options.Password = ""
	options.CredentialsProviderContext = provider
	tlsConfig, err := buildTLSConfig(config, tls.VersionTLS12)
	if err != nil {
		return nil, err
	}
	options.TLSConfig = tlsConfig
	return options, nil
}

// buildTLSConfig leaves ServerName empty: the TLS dialer takes it from the
// address it dials, which on a cluster is each node's own address.
func buildTLSConfig(config Config, minVersion uint16) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         minVersion,
		InsecureSkipVerify: config.TLSInsecureVerify, // #nosec G402 -- callers opt in via config
	}
	if config.TLSCAFile == "" {
		return tlsConfig, nil
	}
	if config.TLSInsecureVerify {
		return nil, errRedisTLSCAInsecure
	}
	roots, err := loadCertPool(config.TLSCAFile)
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = roots
	return tlsConfig, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) // #nosec G304 -- the path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("read redis TLS CA file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("redis TLS CA file %q holds no PEM certificate", path)
	}
	return roots, nil
}

func NewClient(config Config, manager *TTLMapManager, logger *slog.Logger) (Client, error) {
	return newClient(config, manager, logger, defaultRedisAuthDependencies())
}

func newClient(config Config, manager *TTLMapManager, logger *slog.Logger, deps redisAuthDependencies) (Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider, err := newCredentialsProvider(ctx, &config, deps)
	if err != nil {
		return nil, fmt.Errorf("configure redis authentication: %w", err)
	}

	options, err := buildRedisOptions(config, provider)
	if err != nil {
		return nil, fmt.Errorf("configure redis TLS: %w", err)
	}
	redisClient := newUniversalClient(options, config.Cluster)

	if err := redisClient.Ping(ctx).Err(); err != nil {
		_ = redisClient.Close()
		logger.Error("failed to connect to redis",
			slog.String("host", config.Host),
			slog.Int("port", config.Port),
			slog.Bool("cluster", config.Cluster),
			slog.String("error", err.Error()),
		)
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Info(bootlog.RedisConnected,
		slog.String("host", config.Host),
		slog.Int("port", config.Port),
		slog.Bool("cluster", config.Cluster),
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

func (c *client) RedisClient() redis.UniversalClient {
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
