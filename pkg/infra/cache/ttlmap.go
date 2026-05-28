// Package cache hosts in-process and (later) Redis-backed caching
// primitives used by the application layer. B.2 ships only the local
// TTLMap and its namespace manager — RUN-291 will add the Redis client
// and the cross-process invalidation pub/sub, slotting in **between**
// the TTLMap and the database without changing the finder contract.
package cache

import (
	"sync"
	"time"
)

// TTLEntry is a value associated with an expiry instant.
type TTLEntry struct {
	Value     any
	ExpiresAt time.Time
}

// TTLMap is a thread-safe map that lazily evicts expired entries on
// read. Suitable for per-process hot-path caches; not suitable as a
// source of truth.
type TTLMap struct {
	mu   sync.RWMutex
	data map[string]*TTLEntry
	ttl  time.Duration
}

// NewTTLMap creates a new TTLMap with the given default TTL applied to
// every Set.
func NewTTLMap(ttl time.Duration) *TTLMap {
	return &TTLMap{
		data: make(map[string]*TTLEntry),
		ttl:  ttl,
	}
}

// TTL exposes the default TTL applied to entries.
func (m *TTLMap) TTL() time.Duration { return m.ttl }

// Get returns the value if present and unexpired. Expired entries are
// removed lazily on the read path.
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
		// Re-check under the write lock; a concurrent Set may have
		// refreshed the entry between our RUnlock and Lock.
		if current, ok := m.data[key]; ok && time.Now().After(current.ExpiresAt) {
			delete(m.data, key)
		}
		m.mu.Unlock()
		return nil, false
	}
	return value, true
}

// Set inserts or overwrites the value at key with the manager-default
// TTL.
func (m *TTLMap) Set(key string, value any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = &TTLEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(m.ttl),
	}
}

// Delete removes the entry at key, if present. A missing key is a
// no-op.
func (m *TTLMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

// Len returns the number of entries currently held (including expired
// ones not yet swept).
func (m *TTLMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

// Clear empties the map atomically.
func (m *TTLMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]*TTLEntry)
}
