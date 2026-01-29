package cache

import (
	"sync"
	"time"
)

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

// Clear removes all entries from the TTLMap
func (m *TTLMap) Clear() {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Data = make(map[string]*TTLEntry)
}
