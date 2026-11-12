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

// Package secretref resolves secret references on the planes that load a
// store file. Values live only in this package's memory: they are never
// persisted, logged or reported.
package secretref

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/singleflight"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const (
	defaultFetchTimeout    = 2 * time.Second
	defaultRefreshInterval = 15 * time.Second
	defaultProbeInterval   = 60 * time.Second

	defaultIdleEviction = 2 * time.Hour

	refreshAheadRatio  = 0.8
	refreshJitterRatio = 0.1
	forcedRefreshGap   = 30 * time.Second
	initialBackoff     = 5 * time.Second
	refreshConcurrency = 8
	probeConcurrency   = 4
)

//go:generate mockery --name=Resolver --dir=. --output=./mocks --filename=secretref_resolver_mock.go --case=underscore --with-expecter

// Resolver turns references into values.
type Resolver interface {
	// Resolve returns the value ref names. It checks only what the store
	// itself declares (that it is loaded and that the path is allowed); the
	// gateway's eligibility and the store's gateway allowlist are the
	// caller's to check.
	Resolve(ctx context.Context, ref domain.Ref) (string, error)
	// ForceRefresh re-reads the payloads refs name, at most once per payload
	// every 30 seconds, and reports whether any of them changed. Callers use
	// it when an upstream rejects a credential that came from these
	// references.
	ForceRefresh(ctx context.Context, refs []domain.Ref) (bool, error)
	// OnChange registers fn, called with the payloads whose value changed,
	// appeared after a failure, was withdrawn, or left the cache. Each payload
	// is a Ref with an empty Field. fn runs outside the resolver's locks and
	// may resolve.
	OnChange(fn func(payloads []domain.Ref))
}

//go:generate mockery --name=StoreHealth --dir=. --output=./mocks --filename=secretref_store_health_mock.go --case=underscore --with-expecter

// StoreHealth reports the stores a plane loaded and their health.
type StoreHealth interface {
	Statuses() []secretstore.Status
}

// Options tunes a Cache. Zero fields take their defaults.
type Options struct {
	FetchTimeout    time.Duration
	RefreshInterval time.Duration
	ProbeInterval   time.Duration
	// IdleEviction is how long a payload stays cached, and refreshed, after
	// it was last resolved. It must outlast every cache built from resolved
	// values, so that their readers resolve again before the payload goes.
	IdleEviction time.Duration
	Logger       *slog.Logger
	Meter        metric.Meter
	// Now and Jitter exist for tests. Jitter returns a value in [-1, 1).
	Now    func() time.Time
	Jitter func() float64
}

// Cache is the Resolver and StoreHealth of a plane. Run drives its refresh
// and probe loops.
type Cache struct {
	catalog         secretstore.Catalog
	fetchTimeout    time.Duration
	refreshInterval time.Duration
	probeInterval   time.Duration
	idleEviction    time.Duration
	logger          *slog.Logger
	metrics         *metrics
	now             func() time.Time
	jitter          func() float64

	flights singleflight.Group

	mu        sync.Mutex
	entries   map[string]*entry
	health    map[string]*storeHealth
	listeners []func([]domain.Ref)
}

var (
	_ Resolver    = (*Cache)(nil)
	_ StoreHealth = (*Cache)(nil)
)

// NewCache returns a Cache over catalog.
func NewCache(catalog secretstore.Catalog, opts Options) *Cache {
	c := &Cache{
		catalog:         catalog,
		fetchTimeout:    orDefault(opts.FetchTimeout, defaultFetchTimeout),
		refreshInterval: orDefault(opts.RefreshInterval, defaultRefreshInterval),
		probeInterval:   orDefault(opts.ProbeInterval, defaultProbeInterval),
		idleEviction:    orDefault(opts.IdleEviction, defaultIdleEviction),
		logger:          opts.Logger,
		now:             opts.Now,
		jitter:          opts.Jitter,
		entries:         make(map[string]*entry),
		health:          make(map[string]*storeHealth),
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.jitter == nil {
		c.jitter = func() float64 { return rand.Float64()*2 - 1 } // #nosec G404 -- refresh jitter, not a secret
	}
	meter := opts.Meter
	if meter == nil {
		meter = otel.Meter(meterName)
	}
	c.metrics = newMetrics(meter, c.logger)
	return c
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// OnChange implements Resolver.
func (c *Cache) OnChange(fn func(payloads []domain.Ref)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listeners = append(c.listeners, fn)
}

// Resolve implements Resolver.
func (c *Cache) Resolve(ctx context.Context, ref domain.Ref) (string, error) {
	store, backend, err := c.store(ref)
	if err != nil {
		return "", err
	}
	key := ref.PayloadKey()

	c.mu.Lock()
	e := c.entryLocked(key, ref, store)
	e.lastUsed = c.now()
	res := e.lookup(c.now(), true)
	c.mu.Unlock()

	if res.refresh {
		c.flight(ctx, key, e, backend)
	}
	if res.needFetch {
		if _, err := c.fetch(ctx, key, e, backend); err != nil && ctx.Err() != nil {
			return "", ctx.Err()
		}
		c.mu.Lock()
		res = e.lookup(c.now(), false)
		c.mu.Unlock()
	}
	if res.err != nil {
		return "", res.err
	}
	if res.stale {
		c.metrics.staleServed(ctx, store.Type)
	}
	return res.secret.Select(ref.Field)
}

// ForceRefresh implements Resolver.
func (c *Cache) ForceRefresh(ctx context.Context, refs []domain.Ref) (bool, error) {
	seen := make(map[string]bool, len(refs))
	changed := false
	var firstErr error
	for _, ref := range refs {
		key := ref.PayloadKey()
		if seen[key] {
			continue
		}
		seen[key] = true
		store, backend, err := c.store(ref)
		if err != nil {
			firstErr = firstNonNil(firstErr, err)
			continue
		}
		c.mu.Lock()
		e := c.entryLocked(key, ref, store)
		now := c.now()
		limited := !e.forcedAt.IsZero() && now.Sub(e.forcedAt) < forcedRefreshGap
		if !limited {
			e.forcedAt = now
		}
		c.mu.Unlock()
		if limited {
			continue
		}
		did, err := c.fetch(ctx, key, e, backend)
		c.metrics.forcedRefresh(ctx, did)
		changed = changed || did
		if err != nil {
			firstErr = firstNonNil(firstErr, err)
		}
	}
	if changed {
		return true, nil
	}
	return false, firstErr
}

// InvalidateStore drops every cached payload of the store named name and
// notifies their dependents, for a store whose definition changed.
func (c *Cache) InvalidateStore(name string) {
	var dropped []domain.Ref
	c.mu.Lock()
	for key, e := range c.entries {
		if e.payload.Store == name {
			dropped = append(dropped, e.payload)
			delete(c.entries, key)
			c.flights.Forget(key)
		}
	}
	delete(c.health, name)
	c.mu.Unlock()
	c.notify(dropped)
}

func (c *Cache) store(ref domain.Ref) (*secretstore.Store, secretstore.Backend, error) {
	store, backend, ok := c.catalog.Get(ref.Store)
	if !ok {
		return nil, nil, fmt.Errorf("secret store %q: %w", ref.Store, secretstore.ErrStoreMissing)
	}
	if !store.AllowsPath(ref.Path) {
		return nil, nil, fmt.Errorf("secret store %q: %w", ref.Store, secretstore.ErrPathNotAllowed)
	}
	return store, backend, nil
}

func (c *Cache) entryLocked(key string, ref domain.Ref, store *secretstore.Store) *entry {
	e, ok := c.entries[key]
	if !ok {
		e = &entry{
			payload:   domain.Ref{Store: ref.Store, Path: ref.Path, Version: ref.Version},
			storeType: store.Type,
			policy:    store.Cache.WithDefaults(),
			jitter:    c.jitter(),
		}
		c.entries[key] = e
	}
	return e
}

type fetchResult struct {
	changed bool
	err     error
}

// fetch waits for a read of e's payload, shared with every concurrent caller.
// A cancelled caller gets its context's error; the read goes on.
func (c *Cache) fetch(ctx context.Context, key string, e *entry, backend secretstore.Backend) (bool, error) {
	ch := c.flight(ctx, key, e, backend)
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case r := <-ch:
		res, _ := r.Val.(fetchResult)
		return res.changed, res.err
	}
}

// flight starts a read of e's payload, or joins the one in progress. The read
// runs on a context detached from the callers and bounded by the fetch
// timeout, so a cancelled request neither aborts it nor records the store as
// unavailable.
func (c *Cache) flight(ctx context.Context, key string, e *entry, backend secretstore.Backend) <-chan singleflight.Result {
	return c.flights.DoChan(key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout)
		defer cancel()
		started := time.Now()
		secret, err := backend.Fetch(fctx, e.payload.Path, e.payload.Version)
		c.metrics.fetched(fctx, e.storeType, secretstore.ClassOf(err), time.Since(started))

		c.mu.Lock()
		changed := e.apply(c.now(), secret, err)
		c.recordFetchLocked(e.payload.Store, err)
		c.mu.Unlock()
		// A listener that resolves this payload must start its own read,
		// not join this one, which only ends after the listeners return.
		c.flights.Forget(key)
		if changed {
			c.notify([]domain.Ref{e.payload})
		}
		return fetchResult{changed: changed, err: err}, nil
	})
}

func (c *Cache) notify(payloads []domain.Ref) {
	if len(payloads) == 0 {
		return
	}
	c.mu.Lock()
	listeners := append([]func(payloads []domain.Ref){}, c.listeners...)
	c.mu.Unlock()
	for _, fn := range listeners {
		fn(payloads)
	}
}

func firstNonNil(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
