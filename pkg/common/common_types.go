package common

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// Cache defines the interface for caching operations
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	DeleteAllByGatewayID(ctx context.Context, gatewayID string) error
	Client() *redis.Client
	CreateTTLMap(name string, ttl time.Duration) *TTLMap
	GetTTLMap(name string) *TTLMap
}

// CacheImpl implements the Cache interface
type CacheImpl struct {
	redisClient *redis.Client
	DB          *gorm.DB
	LocalCache  sync.Map
	TTLMaps     sync.Map
	TTL         time.Duration
}

// TTLEntry represents an entry in TTLMap
type TTLEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// TTLMap is a thread-safe map with TTL for each entry
type TTLMap struct {
	Data map[string]*TTLEntry
	Mu   sync.RWMutex
	TTL  time.Duration
}

// NewTTLMap creates a new TTLMap with the specified TTL
func NewTTLMap(ttl time.Duration) *TTLMap {
	return &TTLMap{
		Data: make(map[string]*TTLEntry),
		TTL:  ttl,
	}
}

// Get retrieves a value from the TTLMap if it hasn't expired
func (m *TTLMap) Get(key string) (interface{}, bool) {
	m.Mu.RLock()
	entry, exists := m.Data[key]
	if !exists {
		m.Mu.RUnlock()
		return nil, false
	}
	isExpired := time.Now().After(entry.ExpiresAt)
	value := entry.Value
	m.Mu.RUnlock()

	if isExpired {
		m.Mu.Lock()
		if current, ok := m.Data[key]; ok && time.Now().After(current.ExpiresAt) {
			delete(m.Data, key)
		}
		m.Mu.Unlock()
		return nil, false
	}

	return value, true
}

// Set adds or updates a value in the TTLMap
func (m *TTLMap) Set(key string, value interface{}) {
	m.Mu.Lock()
	defer m.Mu.Unlock()

	m.Data[key] = &TTLEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(m.TTL),
	}
}

// Delete removes a key from the TTLMap
func (m *TTLMap) Delete(key string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	delete(m.Data, key)
}

// CacheKeys holds cache key strings
type CacheKeys struct {
	Gateway string
	Rules   string
	Plugin  string
}

// CacheConfig holds configuration for cache connection
type CacheConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	TLS      bool
}

// Get retrieves a value from cache
func (c *CacheImpl) Get(ctx context.Context, key string) (string, error) {
	if value, ok := c.LocalCache.Load(key); ok {
		str, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("invalid type assertion to string")
		}
		return str, nil
	}
	return c.redisClient.Get(ctx, key).Result()
}

// Set stores a value in cache
func (c *CacheImpl) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	if err := c.redisClient.Set(ctx, key, value, expiration).Err(); err != nil {
		return err
	}
	c.LocalCache.Store(key, value)
	return nil
}

// Client returns the Redis client
func (c *CacheImpl) Client() *redis.Client {
	return c.redisClient
}

// GetCacheKeys returns cache keys for a given gateway ID
func GetCacheKeys(gatewayID string) CacheKeys {
	return CacheKeys{
		Gateway: fmt.Sprintf("gateway:%s", gatewayID),
		Rules:   fmt.Sprintf("rules:%s", gatewayID),
		Plugin:  fmt.Sprintf("plugin:%s", gatewayID),
	}
}
