package cache

import (
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
