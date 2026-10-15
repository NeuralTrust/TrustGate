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
	"strings"
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
	// generation counts the removals (Delete, DeleteByPrefix, Clear), so a
	// fill that read its source before one can be told it is stale.
	generation uint64
}

func NewTTLMap(ttl time.Duration) *TTLMap {
	return &TTLMap{
		data: make(map[string]*TTLEntry),
		ttl:  ttl,
	}
}

func (m *TTLMap) TTL() time.Duration { return m.ttl }

// SetOnEvict registers a callback run with each value as it leaves the map (via
// Set replacement, Delete, Clear or TTL expiry), letting a namespace release
// resources tied to cached values. The callback runs outside the map lock.
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
	m.set(key, value, false, 0)
}

// Generation returns the map's current generation. A caller about to read the
// source of a value takes it first and stores the value with
// SetIfGeneration, so an entry removed while it was reading is not put back
// from what it read before the removal.
func (m *TTLMap) Generation() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.generation
}

// SetIfGeneration stores value under key only while the map is still at
// generation, and reports whether it did.
func (m *TTLMap) SetIfGeneration(key string, value any, generation uint64) bool {
	return m.set(key, value, true, generation)
}

func (m *TTLMap) set(key string, value any, checkGeneration bool, generation uint64) bool {
	var (
		evicted any
		onEvict func(any)
		hadPrev bool
	)
	m.mu.Lock()
	if checkGeneration && m.generation != generation {
		m.mu.Unlock()
		return false
	}
	if prev, ok := m.data[key]; ok && m.onEvict != nil {
		evicted = prev.Value
		onEvict = m.onEvict
		hadPrev = true
	}
	m.data[key] = &TTLEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	m.mu.Unlock()
	// Release the value being replaced so resource-owning entries (e.g. a load
	// balancer's background goroutine) cannot leak when a key is overwritten.
	if hadPrev && onEvict != nil {
		onEvict(evicted)
	}
	return true
}

func (m *TTLMap) Delete(key string) {
	var (
		evicted any
		onEvict func(any)
	)
	m.mu.Lock()
	m.generation++
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

// DeleteByPrefix removes every entry whose key starts with prefix, firing
// onEvict for each so resource-owning values (e.g. load balancers keyed by
// "<gatewayID>:<consumerID>") are released. Used to evict all entries scoped to
// a gateway when its configuration changes.
func (m *TTLMap) DeleteByPrefix(prefix string) {
	var evicted []any
	m.mu.Lock()
	m.generation++
	onEvict := m.onEvict
	for k, entry := range m.data {
		if strings.HasPrefix(k, prefix) {
			if onEvict != nil {
				evicted = append(evicted, entry.Value)
			}
			delete(m.data, k)
		}
	}
	m.mu.Unlock()
	for _, value := range evicted {
		onEvict(value)
	}
}

func (m *TTLMap) sweepExpired(now time.Time) {
	var (
		evicted []any
		onEvict func(any)
	)
	m.mu.Lock()
	onEvict = m.onEvict
	for k, entry := range m.data {
		if now.After(entry.ExpiresAt) {
			if onEvict != nil {
				evicted = append(evicted, entry.Value)
			}
			delete(m.data, k)
		}
	}
	m.mu.Unlock()
	for _, value := range evicted {
		onEvict(value)
	}
}

func (m *TTLMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

func (m *TTLMap) Clear() {
	m.mu.Lock()
	m.generation++
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
