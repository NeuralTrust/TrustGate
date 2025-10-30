package cache

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/go-redis/redis/v8"
)

const (
	GatewayKeyPattern   = "gateway:%s"
	RulesKeyPattern     = "rules:%s"
	UpstreamsKeyPattern = "gateway:%s:upstreams"
	UpstreamKeyPattern  = "gateway:%s:upstream:%s"
	ServicesKeyPattern  = "gateway:%s:services"
	ServiceKeyPattern   = "gateway:%s:service:%s"
	ApiKeyPattern       = "apikey:%s"

	GatewayTTLName  = "gateway"
	ApiKeyTTLName   = "api_key"
	RulesTTLName    = "rules"
	PluginTTLName   = "plugin"
	ServiceTTLName  = "service"
	UpstreamTTLName = "upstream"

	DataMaskingTTLName = "data_masking"
)

//go:generate mockery --name=Cache --dir=. --output=./mocks --filename=cache_mock.go --case=underscore --with-expecter
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	Client() *redis.Client
	CreateTTLMap(name string, ttl time.Duration) *TTLMap
	GetTTLMap(name string) *TTLMap

	GetApiKey(ctx context.Context, key string) (*apikey.APIKey, error)
	SaveAPIKey(ctx context.Context, key *apikey.APIKey) error
	GetService(ctx context.Context, gatewayID, serviceID string) (*service.Service, error)
	SaveService(ctx context.Context, gatewayID string, service *service.Service) error
	GetUpstream(ctx context.Context, gatewayID, upstreamID string) (*upstream.Upstream, error)
	SaveUpstream(ctx context.Context, gatewayID string, upstream *upstream.Upstream) error
	DeleteAllPluginsData(ctx context.Context, gatewayID string) error
	DeleteAllByGatewayID(ctx context.Context, gatewayID string) error
}

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
	TLS      bool
}

type cache struct {
	client     *redis.Client
	localCache sync.Map
	ttlMaps    sync.Map
	ttl        time.Duration
}

func NewCache(config Config) (Cache, error) {
	options := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
	}
	if config.TLS {
		options.TLSConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402
		}
	}
	client := redis.NewClient(options)

	return &cache{
		client:     client,
		localCache: sync.Map{},
		ttlMaps:    sync.Map{},
		ttl:        5 * time.Minute,
	}, nil
}

func (c *cache) Get(ctx context.Context, key string) (string, error) {
	if value, ok := c.localCache.Load(key); ok {
		str, err := safeStringCast(value)
		if err != nil {
			return "", fmt.Errorf("cache value error: %w", err)
		}
		return str, nil
	}
	return c.client.Get(ctx, key).Result()
}

func (c *cache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return err
	}
	c.localCache.Store(key, value)
	return nil
}

func (c *cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return err
	}
	c.localCache.Delete(key)
	return nil
}

func (c *cache) DeleteAllPluginsData(ctx context.Context, gatewayID string) error {
	pattern := fmt.Sprintf("*plugin:%s*", gatewayID)
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("error scanning keys: %w", err)
		}
		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
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

func (c *cache) DeleteAllByGatewayID(ctx context.Context, gatewayID string) error {
	pattern := fmt.Sprintf("*%s*", gatewayID)
	var cursor uint64
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("error scanning keys: %w", err)
		}
		if len(keys) > 0 {
			if err := c.client.Del(ctx, keys...).Err(); err != nil {
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

func (c *cache) Client() *redis.Client {
	return c.client
}

func (c *cache) CreateTTLMap(name string, ttl time.Duration) *TTLMap {
	ttlMap := NewTTLMap(ttl)
	c.ttlMaps.Store(name, ttlMap)
	return ttlMap
}

func (c *cache) GetTTLMap(name string) *TTLMap {
	if value, ok := c.ttlMaps.Load(name); ok {
		ttlMap, err := safeTTLMapCast(value)
		if err != nil {
			return nil
		}
		return ttlMap
	}
	return nil
}

func (c *cache) SaveUpstream(ctx context.Context, gatewayID string, upstream *upstream.Upstream) error {
	// Cache individual upstream
	upstreamKey := fmt.Sprintf(UpstreamKeyPattern, gatewayID, upstream.ID)
	upstreamJSON, err := json.Marshal(upstream)
	if err != nil {
		return err
	}
	if err := c.Set(ctx, upstreamKey, string(upstreamJSON), 0); err != nil {
		return err
	}
	// Invalidate upstreams list cache
	upstreamsKey := fmt.Sprintf(UpstreamsKeyPattern, gatewayID)
	return c.Delete(ctx, upstreamsKey)
}

func (c *cache) GetUpstream(ctx context.Context, gatewayID, upstreamID string) (*upstream.Upstream, error) {
	upstreamKey := fmt.Sprintf(UpstreamKeyPattern, gatewayID, upstreamID)
	res, err := c.Get(ctx, upstreamKey)
	if err != nil {
		return nil, err
	}
	upstream := new(upstream.Upstream)
	if err := json.Unmarshal([]byte(res), upstream); err != nil {
		return nil, err
	}
	return upstream, nil
}

func (c *cache) GetService(ctx context.Context, gatewayID, serviceID string) (*service.Service, error) {
	key := fmt.Sprintf(ServiceKeyPattern, gatewayID, serviceID)
	res, err := c.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	entity := new(service.Service)
	if err := json.Unmarshal([]byte(res), entity); err != nil {
		return nil, err
	}
	return entity, nil
}

func (c *cache) GetApiKey(ctx context.Context, key string) (*apikey.APIKey, error) {
	apikeyPattern := fmt.Sprintf(ApiKeyPattern, key)
	res, err := c.Get(ctx, apikeyPattern)
	if err != nil {
		return nil, err
	}
	apiKey := new(apikey.APIKey)
	if err := json.Unmarshal([]byte(res), apiKey); err != nil {
		return nil, err
	}
	return apiKey, nil
}

func (c *cache) SaveService(ctx context.Context, gatewayID string, service *service.Service) error {
	// Cache individual service
	serviceKey := fmt.Sprintf(ServiceKeyPattern, gatewayID, service.ID)
	serviceJSON, err := json.Marshal(service)
	if err != nil {
		return err
	}
	if err := c.Set(ctx, serviceKey, string(serviceJSON), 0); err != nil {
		return err
	}

	// Invalidate services list cache
	servicesKey := fmt.Sprintf(ServicesKeyPattern, gatewayID)
	return c.Delete(ctx, servicesKey)
}

func safeStringCast(value interface{}) (string, error) {
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type assertion to string")
	}
	return str, nil
}

func safeTTLMapCast(value interface{}) (*TTLMap, error) {
	ttlMap, ok := value.(*TTLMap)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion to TTLMap")
	}
	return ttlMap, nil
}
