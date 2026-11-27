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
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTTLMap_GetSetDelete(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(50 * time.Millisecond)

	if _, ok := m.Get("missing"); ok {
		t.Fatal("Get on empty map returned ok=true")
	}

	m.Set("k", "v")
	v, ok := m.Get("k")
	if !ok {
		t.Fatal("Get after Set returned ok=false")
	}
	if v != "v" {
		t.Fatalf("Get returned %v, want \"v\"", v)
	}

	m.Delete("k")
	if _, ok := m.Get("k"); ok {
		t.Fatal("Get after Delete returned ok=true")
	}
}

func TestTTLMap_DeleteByPrefix(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(time.Minute)

	var evicted []any
	m.SetOnEvict(func(v any) { evicted = append(evicted, v) })

	m.Set("gw1:c1", "a")
	m.Set("gw1:c2", "b")
	m.Set("gw2:c1", "keep")

	m.DeleteByPrefix("gw1:")

	if _, ok := m.Get("gw1:c1"); ok {
		t.Fatal("gw1:c1 was not evicted")
	}
	if _, ok := m.Get("gw1:c2"); ok {
		t.Fatal("gw1:c2 was not evicted")
	}
	if _, ok := m.Get("gw2:c1"); !ok {
		t.Fatal("gw2:c1 must be preserved")
	}
	if len(evicted) != 2 {
		t.Fatalf("onEvict fired %d times, want 2", len(evicted))
	}
}

func TestTTLMap_Expiry(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(20 * time.Millisecond)
	m.Set("k", "v")
	if _, ok := m.Get("k"); !ok {
		t.Fatal("Get within TTL returned ok=false")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := m.Get("k"); ok {
		t.Fatal("Get after TTL returned ok=true")
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("expired entry not swept on read: Len=%d", got)
	}
}

func TestTTLMap_Clear(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(time.Hour)
	m.Set("a", 1)
	m.Set("b", 2)
	if got := m.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	m.Clear()
	if got := m.Len(); got != 0 {
		t.Fatalf("Len after Clear = %d, want 0", got)
	}
}

func TestTTLMap_Concurrent(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(time.Hour)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.Set("k", i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.Get("k")
		}
	}()

	wg.Wait()
}

func TestTTLMap_OnEvict_FiresOnDeleteClearAndExpiry(t *testing.T) {
	t.Parallel()

	t.Run("delete", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(time.Hour)
		var evicted []any
		m.SetOnEvict(func(v any) { evicted = append(evicted, v) })
		m.Set("k", "v")
		m.Delete("k")
		m.Delete("k") // second delete must not evict again
		if len(evicted) != 1 || evicted[0] != "v" {
			t.Fatalf("delete eviction = %v, want [v]", evicted)
		}
	})

	t.Run("clear", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(time.Hour)
		count := 0
		m.SetOnEvict(func(any) { count++ })
		m.Set("a", 1)
		m.Set("b", 2)
		m.Clear()
		if count != 2 {
			t.Fatalf("clear evicted %d entries, want 2", count)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(20 * time.Millisecond)
		got := make(chan any, 1)
		m.SetOnEvict(func(v any) { got <- v })
		m.Set("k", "v")
		time.Sleep(40 * time.Millisecond)
		m.Get("k") // lazy expiry must evict
		select {
		case v := <-got:
			if v != "v" {
				t.Fatalf("expiry eviction = %v, want v", v)
			}
		default:
			t.Fatal("expiry did not trigger eviction callback")
		}
	})
}

func TestTTLMap_SweepExpired_FiresOnEvictWithoutAccess(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(10 * time.Millisecond)
	got := make(chan any, 1)
	m.SetOnEvict(func(v any) { got <- v })
	m.Set("idle", "v")

	time.Sleep(20 * time.Millisecond)
	m.sweepExpired(time.Now())

	select {
	case v := <-got:
		if v != "v" {
			t.Fatalf("sweep eviction = %v, want v", v)
		}
	default:
		t.Fatal("sweepExpired did not fire onEvict for an idle expired entry")
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("Len after sweep = %d, want 0", got)
	}
}

func TestManager_StartJanitor_EvictsIdleEntries(t *testing.T) {
	t.Parallel()
	mgr := NewTTLMapManager(10 * time.Millisecond)
	tm := mgr.CreateTTLMap("lb", 10*time.Millisecond)
	evicted := make(chan any, 1)
	tm.SetOnEvict(func(v any) { evicted <- v })
	tm.Set("idle", "closed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.StartJanitor(ctx, 5*time.Millisecond)

	select {
	case v := <-evicted:
		if v != "closed" {
			t.Fatalf("janitor eviction = %v, want closed", v)
		}
	case <-time.After(time.Second):
		t.Fatal("janitor did not evict an idle expired entry")
	}
}

func TestManager_NamespaceIsolation(t *testing.T) {
	t.Parallel()
	mgr := NewTTLMapManager(time.Hour)
	a := mgr.GetTTLMap("a")
	b := mgr.GetTTLMap("b")
	if a == b {
		t.Fatal("manager returned the same TTLMap for different namespaces")
	}
	a.Set("k", "from-a")
	if _, ok := b.Get("k"); ok {
		t.Fatal("namespace b sees writes from namespace a")
	}
}

func TestManager_GetTTLMap_Idempotent(t *testing.T) {
	t.Parallel()
	mgr := NewTTLMapManager(time.Hour)
	first := mgr.GetTTLMap("x")
	second := mgr.GetTTLMap("x")
	if first != second {
		t.Fatal("manager handed out two different TTLMaps for the same namespace")
	}
}

func TestTTLMap_SetIfGenerationDropsAFillOverlappedByARemoval(t *testing.T) {
	t.Parallel()
	for name, remove := range map[string]func(m *TTLMap){
		"delete":    func(m *TTLMap) { m.Delete("other") },
		"by prefix": func(m *TTLMap) { m.DeleteByPrefix("gw:") },
		"clear":     func(m *TTLMap) { m.Clear() },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := NewTTLMap(time.Minute)
			gen := m.Generation()
			remove(m)
			if m.SetIfGeneration("k", "stale", gen) {
				t.Fatal("a fill read before the removal was stored")
			}
			if _, ok := m.Get("k"); ok {
				t.Fatal("the stale value is in the map")
			}
			if !m.SetIfGeneration("k", "fresh", m.Generation()) {
				t.Fatal("a fill at the current generation was refused")
			}
			if v, _ := m.Get("k"); v != "fresh" {
				t.Fatalf("Get = %v, want fresh", v)
			}
		})
	}
}

func TestTTLMap_SetDoesNotAdvanceTheGeneration(t *testing.T) {
	t.Parallel()
	m := NewTTLMap(time.Minute)
	gen := m.Generation()
	m.Set("a", 1)
	m.Set("a", 2)
	if !m.SetIfGeneration("b", 3, gen) {
		t.Fatal("a plain Set made a concurrent fill look stale")
	}
}

func TestTTLMap_RememberMiss(t *testing.T) {
	t.Parallel()

	t.Run("stores a marker while the generation is current", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(time.Minute)
		if !m.RememberMiss("k", m.Generation(), 10) {
			t.Fatal("expected the miss to be remembered")
		}
		if _, ok := m.Get("k"); !ok {
			t.Fatal("marker missing after RememberMiss")
		}
	})

	t.Run("a clear since the read discards it", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(time.Minute)
		gen := m.Generation()
		m.Clear()
		if m.RememberMiss("k", gen, 10) {
			t.Fatal("a miss read before a clear must not be remembered")
		}
	})

	t.Run("a full map of live entries refuses new keys", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(time.Minute)
		m.Set("a", struct{}{})
		m.Set("b", struct{}{})
		if m.RememberMiss("c", m.Generation(), 2) {
			t.Fatal("expected a full map to refuse a new key")
		}
		if !m.RememberMiss("a", m.Generation(), 2) {
			t.Fatal("refreshing a key already in a full map must succeed")
		}
		if n := m.Len(); n != 2 {
			t.Fatalf("expected 2 entries, got %d", n)
		}
	})

	t.Run("a full map of expired entries is swept before refusing", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(10 * time.Millisecond)
		m.Set("a", struct{}{})
		m.Set("b", struct{}{})
		time.Sleep(20 * time.Millisecond)
		if !m.RememberMiss("c", m.Generation(), 2) {
			t.Fatal("expired entries must not keep the map full")
		}
		if n := m.Len(); n != 1 {
			t.Fatalf("expected only the new entry, got %d", n)
		}
	})

	t.Run("a full map is swept at most once per interval", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(10 * time.Millisecond)
		m.Set("a", struct{}{})
		time.Sleep(20 * time.Millisecond)
		m.lastFullPurge.Store(time.Since(m.created).Nanoseconds() + 1)
		if m.RememberMiss("b", m.Generation(), 1) {
			t.Fatal("a sweep within the interval must be skipped")
		}
		if n := m.Len(); n != 1 {
			t.Fatalf("expected the expired entry to stay until the next sweep, got %d", n)
		}
	})

	t.Run("one sweep looks at a bounded number of entries", func(t *testing.T) {
		t.Parallel()
		const maxEntries = 3 * fullPurgeScanLimit
		m := NewTTLMap(10 * time.Millisecond)
		for i := range maxEntries {
			m.Set(fmt.Sprintf("expired-%d", i), struct{}{})
		}
		time.Sleep(20 * time.Millisecond)
		if !m.RememberMiss("new", m.Generation(), maxEntries) {
			t.Fatal("a sweep of expired entries must make room")
		}
		if n := m.Len(); n < maxEntries-fullPurgeScanLimit+1 {
			t.Fatalf("one sweep removed %d entries, more than the %d it may look at", maxEntries+1-n, fullPurgeScanLimit)
		}
	})

	t.Run("a replaced value goes to onEvict", func(t *testing.T) {
		t.Parallel()
		m := NewTTLMap(time.Minute)
		var evicted []any
		m.SetOnEvict(func(v any) { evicted = append(evicted, v) })
		m.Set("k", "resource")
		if !m.RememberMiss("k", m.Generation(), 10) {
			t.Fatal("expected the miss to be remembered")
		}
		if len(evicted) != 1 || evicted[0] != "resource" {
			t.Fatalf("expected the replaced value to be evicted, got %v", evicted)
		}
	})

	t.Run("concurrent misses never exceed the cap", func(t *testing.T) {
		t.Parallel()
		const maxEntries = 100
		m := NewTTLMap(time.Minute)
		gen := m.Generation()
		var wg sync.WaitGroup
		for i := range 1000 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.RememberMiss(fmt.Sprintf("k-%d", i), gen, maxEntries)
			}()
		}
		wg.Wait()
		if n := m.Len(); n != maxEntries {
			t.Fatalf("expected exactly %d entries, got %d", maxEntries, n)
		}
	})
}

// BenchmarkTTLMap_RememberMissFull measures a miss offered to a map at its cap
// of live entries: the bounded sweep when one is due, and the refusal.
func BenchmarkTTLMap_RememberMissFull(b *testing.B) {
	const maxEntries = 100_000
	m := NewTTLMap(time.Hour)
	for i := range maxEntries {
		m.Set(fmt.Sprintf("live-%d", i), struct{}{})
	}
	b.Run("sweep", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m.lastFullPurge.Store(0)
			m.RememberMiss("new", m.Generation(), maxEntries)
		}
	})
	b.Run("refuse", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			m.RememberMiss("new", m.Generation(), maxEntries)
		}
	})
}
