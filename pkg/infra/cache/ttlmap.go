package cache

import (
	"sync"
	"time"
)

type TTLEntry struct {
	Value     any
	ExpiresAt time.Time
}

type TTLMap struct {
	mu      sync.RWMutex
	data    map[string]*TTLEntry
	ttl     time.Duration
	onEvict func(value any)
}

func NewTTLMap(ttl time.Duration) *TTLMap {
	return &TTLMap{
		data: make(map[string]*TTLEntry),
		ttl:  ttl,
	}
}

func (m *TTLMap) TTL() time.Duration { return m.ttl }

// SetOnEvict registers a callback run with each value as it leaves the map (via
// Delete, Clear or TTL expiry), letting a namespace release resources tied to
// cached values. The callback runs outside the map lock.
func (m *TTLMap) SetOnEvict(fn func(value any)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEvict = fn
}

func (m *TTLMap) Get(key string) (any, bool) {
	m.mu.RLock()
	entry, ok := m.data[key]
	if !ok {
		m.mu.RUnlock()
		return nil, false
	}
	expired := time.Now().After(entry.ExpiresAt)
	value := entry.Value
	m.mu.RUnlock()

	if expired {
		var (
			evicted any
			onEvict func(any)
		)
		m.mu.Lock()
		if current, ok := m.data[key]; ok && time.Now().After(current.ExpiresAt) {
			evicted = current.Value
			onEvict = m.onEvict
			delete(m.data, key)
		}
		m.mu.Unlock()
		if onEvict != nil {
			onEvict(evicted)
		}
		return nil, false
	}
	return value, true
}

func (m *TTLMap) Set(key string, value any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = &TTLEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(m.ttl),
	}
}

func (m *TTLMap) Delete(key string) {
	var (
		evicted any
		onEvict func(any)
	)
	m.mu.Lock()
	if entry, ok := m.data[key]; ok {
		evicted = entry.Value
		onEvict = m.onEvict
		delete(m.data, key)
	}
	m.mu.Unlock()
	if onEvict != nil {
		onEvict(evicted)
	}
}

func (m *TTLMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func (m *TTLMap) Clear() {
	m.mu.Lock()
	old := m.data
	onEvict := m.onEvict
	m.data = make(map[string]*TTLEntry)
	m.mu.Unlock()
	if onEvict != nil {
		for _, entry := range old {
			onEvict(entry.Value)
		}
	}
}
