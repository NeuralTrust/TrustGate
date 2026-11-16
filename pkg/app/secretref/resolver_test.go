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

package secretref

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fetchFunc func(ctx context.Context, path, version string) (secretstore.Secret, error)

type fakeBackend struct {
	mu       sync.Mutex
	fetch    fetchFunc
	fetches  atomic.Int64
	probeErr error
}

func (b *fakeBackend) set(f fetchFunc) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fetch = f
}

func (b *fakeBackend) returns(value string, err error) {
	b.set(func(context.Context, string, string) (secretstore.Secret, error) {
		if err != nil {
			return secretstore.Secret{}, err
		}
		return secretstore.NewStringSecret(value, ""), nil
	})
}

func (b *fakeBackend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	b.fetches.Add(1)
	b.mu.Lock()
	f := b.fetch
	b.mu.Unlock()
	return f(ctx, path, version)
}

func (b *fakeBackend) Probe(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.probeErr
}

type fakeCatalog struct {
	mu      sync.Mutex
	stores  map[string]*secretstore.Store
	backend map[string]secretstore.Backend
	loadErr error
}

func (c *fakeCatalog) Get(name string) (*secretstore.Store, secretstore.Backend, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.stores[strings.ToLower(name)]
	return s, c.backend[strings.ToLower(name)], ok
}

func (c *fakeCatalog) Stores() []*secretstore.Store {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*secretstore.Store, 0, len(c.stores))
	for _, s := range c.stores {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c *fakeCatalog) LoadError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loadErr
}

type fixture struct {
	clock   *clock
	backend *fakeBackend
	catalog *fakeCatalog
	cache   *Cache
	reader  *sdkmetric.ManualReader
	changes chan []domain.Ref
}

const (
	ttl      = 5 * time.Minute
	maxStale = time.Hour
	negTTL   = 30 * time.Second
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		clock:   &clock{now: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)},
		backend: &fakeBackend{},
		reader:  sdkmetric.NewManualReader(),
		changes: make(chan []domain.Ref, 16),
	}
	f.backend.returns("sk-1", nil)
	store := &secretstore.Store{
		Name:         "vault",
		Type:         secretstore.TypeHashiCorpVault,
		AllowedPaths: []string{"ai/"},
		Cache:        secretstore.CachePolicy{TTL: ttl, MaxStale: maxStale, NegativeTTL: negTTL},
	}
	f.catalog = &fakeCatalog{
		stores:  map[string]*secretstore.Store{"vault": store},
		backend: map[string]secretstore.Backend{"vault": f.backend},
	}
	f.cache = NewCache(f.catalog, Options{
		FetchTimeout: time.Second,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Meter:        sdkmetric.NewMeterProvider(sdkmetric.WithReader(f.reader)).Meter(meterName),
		Now:          f.clock.Now,
		Jitter:       func() float64 { return 0 },
	})
	f.cache.OnChange(func(p []domain.Ref) { f.changes <- p })
	return f
}

func ref(path string) domain.Ref { return domain.Ref{Store: "vault", Path: path} }

func (f *fixture) resolve(t *testing.T, r domain.Ref) (string, error) {
	t.Helper()
	return f.cache.Resolve(context.Background(), r)
}

func (f *fixture) mustResolve(t *testing.T, r domain.Ref, want string) {
	t.Helper()
	got, err := f.resolve(t, r)
	if err != nil || got != want {
		t.Fatalf("Resolve(%v) = %q, %v; want %q", r, got, err, want)
	}
}

func (f *fixture) noChange(t *testing.T) {
	t.Helper()
	select {
	case p := <-f.changes:
		t.Fatalf("unexpected change notification %v", p)
	default:
	}
}

func (f *fixture) changed(t *testing.T) []domain.Ref {
	t.Helper()
	select {
	case p := <-f.changes:
		return p
	default:
		t.Fatal("expected a change notification")
		return nil
	}
}

func (f *fixture) counter(t *testing.T, name string) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := f.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T", name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				var labels []string
				for _, kv := range dp.Attributes.ToSlice() {
					labels = append(labels, string(kv.Key)+"="+kv.Value.String())
				}
				out[strings.Join(labels, ",")] += dp.Value
			}
		}
	}
	return out
}

func TestResolveChecksStoreAndPathWithoutFetching(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := f.resolve(t, domain.Ref{Store: "missing", Path: "ai/x"}); secretstore.ClassOf(err) != secretstore.ClassStoreMissing {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := f.resolve(t, ref("payments/db")); secretstore.ClassOf(err) != secretstore.ClassPathNotAllowed {
		t.Fatalf("path outside allowed_paths: %v", err)
	}
	if n := f.backend.fetches.Load(); n != 0 {
		t.Fatalf("fetches = %d, want 0", n)
	}
}

func TestResolveSelectsFieldsOfOnePayload(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.backend.set(func(context.Context, string, string) (secretstore.Secret, error) {
		return secretstore.NewFieldsSecret(map[string]string{"key": "k", "org": "o"}, "3"), nil
	})
	r := ref("ai/openai")
	r.Field = "key"
	f.mustResolve(t, r, "k")
	r.Field = "org"
	f.mustResolve(t, r, "o")
	r.Field = "absent"
	if _, err := f.resolve(t, r); secretstore.ClassOf(err) != secretstore.ClassFieldNotFound {
		t.Fatalf("absent field: %v", err)
	}
	r.Field = "key"
	f.mustResolve(t, r, "k")
	if n := f.backend.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1 for every field of one payload", n)
	}
}

func TestConcurrentColdMissFetchesOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	release := make(chan struct{})
	f.backend.set(func(context.Context, string, string) (secretstore.Secret, error) {
		<-release
		return secretstore.NewStringSecret("sk-1", ""), nil
	})
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := f.cache.Resolve(context.Background(), ref("ai/openai"))
			if err == nil && v != "sk-1" {
				err = fmt.Errorf("got %q", v)
			}
			errs <- err
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.backend.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestAuthFailedServesStale(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.backend.returns("", secretstore.ErrAuthFailed)
	f.clock.Advance(ttl)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
}

func TestSameValueDoesNotNotify(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.clock.Advance(ttl * 9 / 10)
	f.cache.refreshTick(context.Background())
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("refresh-ahead fetches = %d, want 2", n)
	}
	f.noChange(t)

	f.backend.returns("sk-2", nil)
	f.clock.Advance(ttl * 9 / 10)
	f.cache.refreshTick(context.Background())
	f.changed(t)
	f.mustResolve(t, ref("ai/openai"), "sk-2")
}

func TestColdTransientFailureBacksOff(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.backend.returns("", secretstore.ErrUnavailable)
	for range 3 {
		if _, err := f.resolve(t, ref("ai/openai")); secretstore.ClassOf(err) != secretstore.ClassUnavailable {
			t.Fatalf("cold miss: %v", err)
		}
	}
	if n := f.backend.fetches.Load(); n != 1 {
		t.Fatalf("fetches during backoff = %d, want 1", n)
	}
	f.clock.Advance(initialBackoff)
	_, _ = f.resolve(t, ref("ai/openai"))
	f.clock.Advance(initialBackoff)
	_, _ = f.resolve(t, ref("ai/openai"))
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2: the second backoff doubles to 10s", n)
	}

	f.backend.returns("sk-1", nil)
	f.clock.Advance(2 * initialBackoff)
	f.cache.refreshTick(context.Background())
	if p := f.changed(t); len(p) != 1 {
		t.Fatalf("recovery must notify dependents built without the value, got %v", p)
	}
	f.mustResolve(t, ref("ai/openai"), "sk-1")
}

func TestPinnedVersionNeverRefreshesAndIsEvicted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var versions []string
	var mu sync.Mutex
	f.backend.set(func(_ context.Context, _, version string) (secretstore.Secret, error) {
		mu.Lock()
		versions = append(versions, version)
		mu.Unlock()
		return secretstore.NewStringSecret("v"+version, version), nil
	})
	pinned := ref("ai/openai")
	pinned.Version = "7"
	f.mustResolve(t, pinned, "v7")
	for range 4 {
		f.clock.Advance(ttl)
		f.cache.refreshTick(context.Background())
		f.mustResolve(t, pinned, "v7")
	}
	if n := f.backend.fetches.Load(); n != 1 {
		t.Fatalf("pinned fetches = %d, want 1", n)
	}
	f.clock.Advance(defaultIdleEviction)
	f.cache.refreshTick(context.Background())
	f.changed(t)
	f.mustResolve(t, pinned, "v7")
	if n := f.backend.fetches.Load(); n != 2 || versions[1] != "7" {
		t.Fatalf("after eviction fetches = %d versions %v, want a second read of version 7", n, versions)
	}
}

func TestIdleEntriesAreEvicted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.clock.Advance(defaultIdleEviction)
	f.cache.refreshTick(context.Background())
	f.cache.mu.Lock()
	n := len(f.cache.entries)
	f.cache.mu.Unlock()
	if n != 0 {
		t.Fatalf("entries = %d, want 0", n)
	}
	if p := f.changed(t); len(p) != 1 {
		t.Fatalf("evicting a value must notify its readers, got %v", p)
	}
	f.backend.returns("", secretstore.ErrNotFound)
	_, _ = f.resolve(t, ref("ai/gone"))
	f.clock.Advance(defaultIdleEviction)
	f.cache.refreshTick(context.Background())
	f.noChange(t)
}

func TestForceRefresh(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	r := ref("ai/openai")
	f.mustResolve(t, r, "sk-1")

	changed, err := f.cache.ForceRefresh(context.Background(), []domain.Ref{r, r})
	if err != nil || changed {
		t.Fatalf("same value: changed %v, err %v", changed, err)
	}
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 (duplicates collapse)", n)
	}

	f.backend.returns("sk-2", nil)
	f.clock.Advance(forcedRefreshGap - time.Second)
	if changed, _ := f.cache.ForceRefresh(context.Background(), []domain.Ref{r}); changed {
		t.Fatal("a forced refresh inside 30s must be skipped")
	}
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}

	f.clock.Advance(time.Second)
	changed, err = f.cache.ForceRefresh(context.Background(), []domain.Ref{r})
	if err != nil || !changed {
		t.Fatalf("rotated value: changed %v, err %v", changed, err)
	}
	f.changed(t)
	f.mustResolve(t, r, "sk-2")
	got := f.counter(t, forcedRefreshesMetric)
	if got["changed=false"] != 1 || got["changed=true"] != 1 {
		t.Fatalf("forced refreshes = %v", got)
	}
}

func TestForceRefreshBypassesNegativeCache(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.backend.returns("", secretstore.ErrNotFound)
	_, _ = f.resolve(t, ref("ai/openai"))
	f.backend.returns("sk-1", nil)
	changed, err := f.cache.ForceRefresh(context.Background(), []domain.Ref{ref("ai/openai")})
	if err != nil || !changed {
		t.Fatalf("changed %v, err %v", changed, err)
	}
}

func TestCallerCancellationDoesNotPoisonTheCache(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	f.backend.set(func(ctx context.Context, _, _ string) (secretstore.Secret, error) {
		close(started)
		select {
		case <-release:
			return secretstore.NewStringSecret("sk-1", ""), nil
		case <-ctx.Done():
			return secretstore.Secret{}, ctx.Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := f.cache.Resolve(ctx, ref("ai/openai"))
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller got %v", err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for f.counter(t, fetchesMetric)["result=ok,store_type=hashicorp_vault"] != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("the shared fetch did not complete: %v", f.counter(t, fetchesMetric))
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	if n := f.backend.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	if got := f.counter(t, fetchesMetric); got["result=unavailable,store_type=hashicorp_vault"] != 0 {
		t.Fatalf("cancellation recorded as unavailable: %v", got)
	}
}

func TestInvalidateStore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.cache.InvalidateStore("vault")
	if p := f.changed(t); len(p) != 1 {
		t.Fatalf("changed = %v", p)
	}
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want a fresh read after invalidation", n)
	}
}

func TestStatuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if s := f.cache.Statuses(); len(s) != 1 || s[0].State != secretstore.StateOK || !s[0].CheckedAt.IsZero() {
		t.Fatalf("before any check: %+v", s)
	}

	f.backend.mu.Lock()
	f.backend.probeErr = fmt.Errorf("login: %w", secretstore.ErrAuthFailed)
	f.backend.mu.Unlock()
	f.cache.probeTick(context.Background())
	s := f.cache.Statuses()[0]
	if s.State != secretstore.StateAuthFailed || s.ErrorClass != secretstore.ClassAuthFailed || s.CheckedAt.IsZero() {
		t.Fatalf("after a failed probe: %+v", s)
	}

	f.clock.Advance(time.Second)
	f.backend.returns("", secretstore.ErrNotFound)
	_, _ = f.resolve(t, ref("ai/missing"))
	if s := f.cache.Statuses()[0]; s.State != secretstore.StateOK {
		t.Fatalf("a missing path must not mark the store down: %+v", s)
	}

	f.clock.Advance(time.Second)
	f.backend.returns("", secretstore.ErrUnavailable)
	_, _ = f.resolve(t, ref("ai/other"))
	if s := f.cache.Statuses()[0]; s.State != secretstore.StateUnavailable {
		t.Fatalf("after an unavailable fetch: %+v", s)
	}

	f.catalog.mu.Lock()
	f.catalog.loadErr = errors.New("bad yaml")
	f.catalog.mu.Unlock()
	if s := f.cache.Statuses()[0]; s.State != secretstore.StateConfigError {
		t.Fatalf("after a failed reload: %+v", s)
	}
	if got := f.counter(t, probesMetric); got["result=auth_failed,store_type=hashicorp_vault"] != 1 {
		t.Fatalf("probes = %v", got)
	}
}

func TestMetricLabelsCarryNoPathOrValue(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.backend.returns("sk-live-do-not-leak", nil)
	f.mustResolve(t, ref("ai/openai"), "sk-live-do-not-leak")
	for _, name := range []string{fetchesMetric, staleServedMetric, forcedRefreshesMetric, probesMetric} {
		for labels := range f.counter(t, name) {
			if strings.Contains(labels, "openai") || strings.Contains(labels, "sk-live") || strings.Contains(labels, "vault=") {
				t.Fatalf("%s labels %q leak a path or value", name, labels)
			}
		}
	}
}

func (f *fixture) awaitChange(t *testing.T) []domain.Ref {
	t.Helper()
	select {
	case p := <-f.changes:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("expected a change notification")
		return nil
	}
}

func (f *fixture) awaitFetches(t *testing.T, n int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for f.counter(t, fetchesMetric)["result=ok,store_type=hashicorp_vault"]+f.failedFetches(t) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d completed fetches, have %v", n, f.counter(t, fetchesMetric))
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (f *fixture) failedFetches(t *testing.T) int64 {
	t.Helper()
	var n int64
	for labels, v := range f.counter(t, fetchesMetric) {
		if !strings.Contains(labels, "result=ok") {
			n += v
		}
	}
	return n
}

func TestResolveCachesUntilTTL(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.clock.Advance(ttl - time.Second)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	if n := f.backend.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	f.clock.Advance(2 * time.Second)
	f.backend.returns("sk-2", nil)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	if p := f.awaitChange(t); len(p) != 1 || p[0] != ref("ai/openai") {
		t.Fatalf("changed = %v", p)
	}
	f.mustResolve(t, ref("ai/openai"), "sk-2")
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2 after the TTL", n)
	}
}

func TestStaleThenDead(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.backend.returns("", fmt.Errorf("dial: %w", secretstore.ErrUnavailable))

	f.clock.Advance(ttl + time.Minute)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.awaitFetches(t, 2)
	f.clock.Advance(time.Second)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	if got := f.counter(t, staleServedMetric)["store_type=hashicorp_vault"]; got != 2 {
		t.Fatalf("stale served = %d, want 2", got)
	}
	if n := f.backend.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2: the second resolve falls inside the backoff", n)
	}

	f.clock.Advance(maxStale - 2*time.Minute)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.clock.Advance(2 * time.Minute)
	f.cache.refreshTick(context.Background())
	if p := f.awaitChange(t); len(p) != 1 {
		t.Fatalf("expiry must notify dependents, got %v", p)
	}
	if _, err := f.resolve(t, ref("ai/openai")); secretstore.ClassOf(err) != secretstore.ClassUnavailable {
		t.Fatalf("past max_stale: %v", err)
	}
}

func TestStaleNeverWaitsForTheStore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	release := make(chan struct{})
	defer close(release)
	f.backend.set(func(context.Context, string, string) (secretstore.Secret, error) {
		<-release
		return secretstore.Secret{}, secretstore.ErrUnavailable
	})
	f.clock.Advance(ttl)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if v, err := f.cache.Resolve(ctx, ref("ai/openai")); err != nil || v != "sk-1" {
		t.Fatalf("a stale value must be served without waiting for the store: %q, %v", v, err)
	}
}

func TestSteadyRebuildsKeepStaleForMaxStale(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.catalog.mu.Lock()
	f.catalog.stores["vault"].Cache.MaxStale = 24 * time.Hour
	f.catalog.mu.Unlock()
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.backend.returns("", secretstore.ErrUnavailable)
	for elapsed := time.Duration(0); elapsed < 23*time.Hour; elapsed += 59 * time.Minute {
		f.clock.Advance(59 * time.Minute)
		f.cache.refreshTick(context.Background())
		f.mustResolve(t, ref("ai/openai"), "sk-1")
	}
}

func TestRevocationWithdrawsTheValue(t *testing.T) {
	t.Parallel()
	for _, denial := range []error{secretstore.ErrNotFound, secretstore.ErrAccessDenied} {
		t.Run(string(secretstore.ClassOf(denial)), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.mustResolve(t, ref("ai/openai"), "sk-1")
			f.backend.returns("", denial)
			f.clock.Advance(ttl * 9 / 10)
			f.cache.refreshTick(context.Background())
			if p := f.awaitChange(t); len(p) != 1 || p[0] != ref("ai/openai") {
				t.Fatalf("revocation must notify dependents, got %v", p)
			}
			if _, err := f.resolve(t, ref("ai/openai")); !errors.Is(err, denial) {
				t.Fatalf("revoked secret resolved: %v", err)
			}
			before := f.backend.fetches.Load()
			f.clock.Advance(negTTL - time.Second)
			if _, err := f.resolve(t, ref("ai/openai")); !errors.Is(err, denial) {
				t.Fatalf("negative cache: %v", err)
			}
			if f.backend.fetches.Load() != before {
				t.Fatal("a negative entry must not fetch again before negative_ttl")
			}
		})
	}
}

func TestListenerMayResolve(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.mustResolve(t, ref("ai/openai"), "sk-1")
	f.backend.returns("", secretstore.ErrNotFound)

	var fired atomic.Bool
	resolved := make(chan error, 1)
	f.cache.OnChange(func([]domain.Ref) {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		f.backend.returns("sk-3", nil)
		f.clock.Advance(negTTL)
		_, err := f.cache.Resolve(context.Background(), ref("ai/openai"))
		resolved <- err
	})
	f.clock.Advance(ttl * 9 / 10)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.cache.refreshTick(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a listener that resolves the same payload deadlocked the cache")
	}
	if err := <-resolved; err != nil {
		t.Fatalf("listener resolve: %v", err)
	}
}

func TestInvalidateStoreDuringFetch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	release := make(chan struct{})
	var calls atomic.Int64
	f.backend.set(func(context.Context, string, string) (secretstore.Secret, error) {
		if calls.Add(1) == 1 {
			<-release
			return secretstore.Secret{}, secretstore.ErrUnavailable
		}
		return secretstore.NewStringSecret("sk-new", ""), nil
	})
	go func() { _, _ = f.cache.Resolve(context.Background(), ref("ai/openai")) }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	f.cache.InvalidateStore("vault")
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if v, err := f.cache.Resolve(ctx, ref("ai/openai")); err != nil || v != "sk-new" {
		t.Fatalf("a resolve after invalidation joined the dropped read: %q, %v", v, err)
	}
}

func TestForceRefreshOfAnUncachedPayloadKeepsIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	r := ref("ai/openai")
	if _, err := f.cache.ForceRefresh(context.Background(), []domain.Ref{r}); err != nil {
		t.Fatal(err)
	}
	f.cache.refreshTick(context.Background())
	f.cache.mu.Lock()
	n := len(f.cache.entries)
	f.cache.mu.Unlock()
	if n != 1 {
		t.Fatalf("entries = %d; a payload read by a forced refresh must not count as idle", n)
	}
}
