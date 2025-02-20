package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/models"
)

// Cache implements the common.Cache interface
type Cache struct {
	client     *redis.Client
	db         *gorm.DB
	localCache sync.Map
	ttlMaps    sync.Map
	ttl        time.Duration
}

// Add new cache key patterns
const (
	// Existing patterns
	GatewayKeyPattern = "gateway:%s"
	RulesKeyPattern   = "rules:%s"

	// New patterns
	UpstreamsKeyPattern = "gateway:%s:upstreams"   // List of upstreams for a gateway
	UpstreamKeyPattern  = "gateway:%s:upstream:%s" // Single upstream
	ServicesKeyPattern  = "gateway:%s:services"    // List of services for a gateway
	ServiceKeyPattern   = "gateway:%s:service:%s"  // Single service
)

func NewCache(config common.CacheConfig, db *gorm.DB) (*Cache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
	})

	return &Cache{
		client:     client,
		db:         db,
		localCache: sync.Map{},
		ttlMaps:    sync.Map{},
		ttl:        5 * time.Minute,
	}, nil
}

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	if value, ok := c.localCache.Load(key); ok {
		str, err := safeStringCast(value)
		if err != nil {
			return "", fmt.Errorf("cache value error: %w", err)
		}
		return str, nil
	}
	return c.client.Get(ctx, key).Result()
}

func (c *Cache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return err
	}
	c.localCache.Store(key, value)
	return nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return err
	}
	c.localCache.Delete(key)
	return nil
}

func (c *Cache) Client() *redis.Client {
	return c.client
}

func (c *Cache) CreateTTLMap(name string, ttl time.Duration) *common.TTLMap {
	ttlMap := common.NewTTLMap(ttl)
	c.ttlMaps.Store(name, ttlMap)
	return ttlMap
}

func (c *Cache) GetTTLMap(name string) *common.TTLMap {
	if value, ok := c.ttlMaps.Load(name); ok {
		ttlMap, err := safeTTLMapCast(value)
		if err != nil {
			return nil
		}
		return ttlMap
	}
	return nil
}

// Add new cache methods
func (c *Cache) SaveUpstream(ctx context.Context, gatewayID string, upstream *models.Upstream) error {
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

func (c *Cache) GetUpstream(ctx context.Context, gatewayID string, upstreamID string) (*models.Upstream, error) {
	var upstream *models.Upstream
	upstreamKey := fmt.Sprintf(UpstreamKeyPattern, gatewayID, upstreamID)
	res, err := c.Get(ctx, upstreamKey)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(res), &upstream); err != nil {
		return nil, err
	}
	return upstream, nil
}

func (c *Cache) GetService(ctx context.Context, gatewayID string, serviceID string) (*models.Service, error) {
	var service *models.Service
	key := fmt.Sprintf(ServiceKeyPattern, gatewayID, serviceID)
	res, err := c.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(res), &service); err != nil {
		return nil, err
	}
	return service, nil
}

func (c *Cache) SaveService(ctx context.Context, gatewayID string, service *models.Service) error {
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

func safeTTLMapCast(value interface{}) (*common.TTLMap, error) {
	ttlMap, ok := value.(*common.TTLMap)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion to TTLMap")
	}
	return ttlMap, nil
}
