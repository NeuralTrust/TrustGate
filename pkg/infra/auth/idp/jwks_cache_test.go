package idp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newCountingJWKSServer(t *testing.T, requests *atomic.Int32, failing *atomic.Bool, delay time.Duration) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if delay > 0 {
			time.Sleep(delay)
		}
		if failing != nil && failing.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{{KeyID: "kid-1", KeyType: "RSA"}}}))
	}))
	t.Cleanup(server.Close)
	return server
}

func adjustableClock(start time.Time) (func() time.Time, func(d time.Duration)) {
	var mu sync.Mutex
	now := start
	return func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}, func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(d)
		}
}

func TestJWKSCache_ConcurrentGetsShareSingleFetch(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := newCountingJWKSServer(t, &requests, nil, 50*time.Millisecond)

	cache := NewJWKSCache(server.Client(), time.Minute)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys, err := cache.Get(context.Background(), server.URL)
			if err == nil && len(keys.Keys) != 1 {
				err = errors.New("unexpected key set")
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1 (single-flight)", got)
	}
}

func TestJWKSCache_ForcedRefreshIsRateLimited(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := newCountingJWKSServer(t, &requests, nil, 0)

	cache := NewJWKSCache(server.Client(), time.Minute)
	clock, advance := adjustableClock(time.Now())
	cache.now = clock

	if _, err := cache.Get(context.Background(), server.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := cache.Refresh(context.Background(), server.URL); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2 after first forced refresh", got)
	}

	keys, err := cache.Refresh(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("rate-limited Refresh: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("rate-limited Refresh must serve the cached set, got %+v", keys)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2 (refresh inside the interval must not fetch)", got)
	}

	advance(defaultRefreshInterval + time.Second)
	if _, err := cache.Refresh(context.Background(), server.URL); err != nil {
		t.Fatalf("Refresh after interval: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("JWKS requests = %d, want 3 after the interval elapsed", got)
	}
}

func TestJWKSCache_ServesStaleSetWhenFetchFails(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	var failing atomic.Bool
	server := newCountingJWKSServer(t, &requests, &failing, 0)

	cache := NewJWKSCache(server.Client(), time.Minute)
	clock, advance := adjustableClock(time.Now())
	cache.now = clock

	keys, err := cache.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("unexpected initial key set: %+v", keys)
	}

	failing.Store(true)
	advance(2 * time.Minute) // cached set is now expired

	keys, err = cache.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get with failing endpoint must serve the stale set, got error: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("stale set mismatch: %+v", keys)
	}

	keys, err = cache.Refresh(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Refresh with failing endpoint must serve the stale set, got error: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("stale set mismatch after refresh: %+v", keys)
	}
}

func TestJWKSCache_FetchFailureWithoutPriorSetReturnsFetchError(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	var failing atomic.Bool
	failing.Store(true)
	server := newCountingJWKSServer(t, &requests, &failing, 0)

	cache := NewJWKSCache(server.Client(), time.Minute)
	_, err := cache.Get(context.Background(), server.URL)
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("err = %v, want ErrJWKSFetch", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatalf("fetch failures must not be ErrInvalidToken, got %v", err)
	}
}
