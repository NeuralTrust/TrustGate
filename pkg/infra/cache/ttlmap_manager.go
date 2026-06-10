package cache

import (
	"sync"
	"time"
)

const (
	GatewayTTLName      = "gateway"
	RegistryTTLName     = "backend"
	ConsumerTTLName     = "consumer"
	RoleTTLName         = "role"
	ConsumerDataTTLName = "consumer_data"
	PolicyTTLName       = "policy"
	AuthTTLName         = "auth"
	AuthKeyTTLName      = "auth_key"
	LoadBalancerTTLName = "lb"
	// CatalogModelTTLName indexes catalog models by "providerCode:slug" for the
	// proxy plane's cost computation, so pricing avoids a DB round-trip on the
	// hot path after the first lookup.
	CatalogModelTTLName = "catalog_model"
)

const (
	GatewayCacheTTL      = 1 * time.Hour
	RegistryCacheTTL     = 5 * time.Minute
	ConsumerCacheTTL     = 5 * time.Minute
	RoleCacheTTL         = 5 * time.Minute
	ConsumerDataCacheTTL = 1 * time.Hour
	PolicyCacheTTL       = 5 * time.Minute
	AuthCacheTTL         = 5 * time.Minute
	AuthKeyCacheTTL      = 5 * time.Minute
	LoadBalancerCacheTTL = 5 * time.Minute
	CatalogModelCacheTTL = 24 * time.Hour
)

type TTLMapManager struct {
	mu         sync.Mutex
	maps       map[string]*TTLMap
	defaultTTL time.Duration
}

func NewTTLMapManager(defaultTTL time.Duration) *TTLMapManager {
	return &TTLMapManager{
		maps:       make(map[string]*TTLMap),
		defaultTTL: defaultTTL,
	}
}

func (m *TTLMapManager) GetTTLMap(name string) *TTLMap {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.maps[name]; ok {
		return cached
	}
	tm := NewTTLMap(m.defaultTTL)
	m.maps[name] = tm
	return tm
}

func (m *TTLMapManager) CreateTTLMap(name string, ttl time.Duration) *TTLMap {
	m.mu.Lock()
	defer m.mu.Unlock()
	tm := NewTTLMap(ttl)
	m.maps[name] = tm
	return tm
}

func (m *TTLMapManager) ClearAllTTLMaps() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tm := range m.maps {
		tm.Clear()
	}
}

func (m *TTLMapManager) DefaultTTL() time.Duration { return m.defaultTTL }
