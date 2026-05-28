package cache

import (
	"sync"
	"time"
)

// Namespace identifiers used by the application layer. Each entity
// owns one. Keep this list close to the consumers — adding an entity
// adds one constant here.
const (
	GatewayTTLName  = "gateway"
	BackendTTLName  = "backend"
	ConsumerTTLName = "consumer"
	PolicyTTLName   = "policy"
	AuthTTLName     = "auth"
)

// TTLMapManager hands out lazily-created TTLMaps per namespace. The
// manager itself is a singleton; the TTLMap it returns for a given
// name is stable for the lifetime of the process.
type TTLMapManager struct {
	mu         sync.Mutex
	maps       map[string]*TTLMap
	defaultTTL time.Duration
}

// NewTTLMapManager builds a manager whose maps default to the given
// TTL on every Set. RUN-291 will extend this with per-namespace TTL
// overrides driven by env config.
func NewTTLMapManager(defaultTTL time.Duration) *TTLMapManager {
	return &TTLMapManager{
		maps:       make(map[string]*TTLMap),
		defaultTTL: defaultTTL,
	}
}

// GetTTLMap returns the TTLMap for the given namespace, creating it
// on first access. Safe for concurrent use.
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

// DefaultTTL exposes the TTL applied to maps freshly created by this
// manager.
func (m *TTLMapManager) DefaultTTL() time.Duration { return m.defaultTTL }
