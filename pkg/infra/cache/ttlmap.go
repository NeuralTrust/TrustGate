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
	mu   sync.RWMutex
	data map[string]*TTLEntry
	ttl  time.Duration
}

func NewTTLMap(ttl time.Duration) *TTLMap {
	return &TTLMap{
		data: make(map[string]*TTLEntry),
		ttl:  ttl,
	}
}

func (m *TTLMap) TTL() time.Duration { return m.ttl }

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
		m.mu.Lock()
		if current, ok := m.data[key]; ok && time.Now().After(current.ExpiresAt) {
			delete(m.data, key)
		}
		m.mu.Unlock()
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
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

func (m *TTLMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func (m *TTLMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]*TTLEntry)
}
