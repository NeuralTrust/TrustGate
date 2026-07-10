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
