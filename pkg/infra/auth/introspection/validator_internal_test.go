package introspection

import (
	"testing"
	"time"
)

func TestSweepLocked_DropsExpiredEntries(t *testing.T) {
	t.Parallel()
	v := NewValidator(nil)
	now := time.Now()
	v.cache["dead"] = cacheEntry{expiresAt: now.Add(-time.Second)}
	v.cache["live"] = cacheEntry{expiresAt: now.Add(time.Minute)}
	v.lastSweep = now.Add(-2 * sweepInterval)

	v.mu.Lock()
	v.sweepLocked()
	v.mu.Unlock()

	if _, ok := v.cache["dead"]; ok {
		t.Fatal("expired entry not purged")
	}
	if _, ok := v.cache["live"]; !ok {
		t.Fatal("live entry must survive the sweep")
	}
}

func TestSweepLocked_RateLimited(t *testing.T) {
	t.Parallel()
	v := NewValidator(nil)
	now := time.Now()
	v.cache["dead"] = cacheEntry{expiresAt: now.Add(-time.Second)}
	v.lastSweep = now

	v.mu.Lock()
	v.sweepLocked()
	v.mu.Unlock()

	if _, ok := v.cache["dead"]; !ok {
		t.Fatal("sweep must not run again within sweepInterval")
	}
}
