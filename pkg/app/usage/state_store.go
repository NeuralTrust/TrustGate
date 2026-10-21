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

// Package usage keeps the control plane's view of every tenant's usage state
// and hands it to the data planes.
package usage

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

//go:generate mockery --name=Applier --dir=. --output=./mocks --filename=applier_mock.go --case=underscore --with-expecter

// Applier records usage states coming from Usage System.
type Applier interface {
	// Apply records individual state changes.
	Apply(ctx context.Context, states []domain.TenantState) error
	// ApplySnapshot records Usage System's full list of exhausted tenants as
	// of asOfVersion.
	ApplySnapshot(ctx context.Context, exhausted []domain.TenantState, asOfVersion int64) error
	// Watermark is the highest version the store has applied, sent back to
	// Usage System when a stream opens.
	Watermark() int64
}

//go:generate mockery --name=Reader --dir=. --output=./mocks --filename=reader_mock.go --case=underscore --with-expecter

// Reader serves the exhausted tenants to the data planes.
type Reader interface {
	// SnapshotAll lists every exhausted tenant.
	SnapshotAll() domain.Snapshot
	// SnapshotTenant lists tenantID when it is exhausted. An empty tenantID
	// lists nothing and still carries the watermark.
	SnapshotTenant(tenantID string) domain.Snapshot
	// Subscribe returns a channel that receives a value after every change,
	// coalescing bursts, and a function that releases it.
	Subscribe() (<-chan struct{}, func())
	// Ready reports whether the store holds a list it can serve.
	Ready() bool
}

// Store is the in-memory usage state of every tenant, backed by a cache that
// lets a control plane start while Usage System is unreachable.
type Store struct {
	cache  domain.StateCache
	logger *slog.Logger
	writer *cacheWriter

	mu           sync.RWMutex
	states       map[string]domain.TenantState
	maxVersion   int64
	snapshotAsOf int64
	complete     bool
	generation   uint64
	ready        atomic.Bool

	subsMu sync.Mutex
	subs   map[chan struct{}]struct{}
}

var (
	_ Applier           = (*Store)(nil)
	_ Reader            = (*Store)(nil)
	_ ExhaustionChecker = (*Store)(nil)
)

// NewStore builds an empty, not yet ready Store. writeTimeout bounds each
// chunk of cache writes and must be positive.
func NewStore(cache domain.StateCache, logger *slog.Logger, writeTimeout time.Duration) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		cache:  cache,
		logger: logger,
		writer: newCacheWriter(cache, writeTimeout, logger),
		states: make(map[string]domain.TenantState),
		subs:   make(map[chan struct{}]struct{}),
	}
}

// Apply records states following TenantState.Supersedes, wakes the
// subscribers and queues the states that changed for the cache.
func (s *Store) Apply(_ context.Context, states []domain.TenantState) error {
	s.publish(s.merge(states))
	return nil
}

// ApplySnapshot records a full list of exhausted tenants as of asOfVersion,
// following domain.Snapshot.Changes. From the first one on, the store's lists
// are complete and carry its watermark as their as_of version.
func (s *Store) ApplySnapshot(_ context.Context, exhausted []domain.TenantState, asOfVersion int64) error {
	s.publish(s.mergeSnapshot(domain.Snapshot{Exhausted: exhausted, AsOfVersion: asOfVersion}))
	return nil
}

// Watermark is the highest version the store has applied.
func (s *Store) Watermark() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxVersion
}

// restore loads the cached states, skipping any that a snapshot applied in
// the meantime already covers. The store becomes ready once it succeeds,
// except when the cache is empty and awaitSync is set: an empty cache says
// nothing, so the store waits for Usage System's first snapshot instead of
// serving an empty list as if nobody were exhausted.
func (s *Store) restore(ctx context.Context, awaitSync bool) error {
	states, err := s.cache.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("usage: load cached states: %w", err)
	}
	changed := s.mergeRestored(states)
	becameReady := false
	if len(states) > 0 || !awaitSync {
		becameReady = s.markReady()
	}
	if len(changed) > 0 || becameReady {
		s.notify()
	}
	return nil
}

// RestoreOptions tune RestoreUntilReady.
type RestoreOptions struct {
	// Interval is the first wait after a failed restore; it doubles up to
	// MaxBackoff.
	Interval   time.Duration
	MaxBackoff time.Duration
	// AwaitSync is set when a UsageSync stream will deliver a snapshot.
	AwaitSync bool
}

// RestoreUntilReady loads the cached states, retrying until it succeeds, the
// store is ready or ctx ends.
func (s *Store) RestoreUntilReady(ctx context.Context, opts RestoreOptions) {
	wait := opts.Interval
	for !s.Ready() {
		err := s.restore(ctx, opts.AwaitSync)
		if err == nil {
			return
		}
		s.logger.WarnContext(ctx, "usage: restore cached states", slog.Any("error", err), slog.Duration("retry_in", wait))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		wait = min(wait*2, opts.MaxBackoff)
	}
}

// Ready reports whether the store holds a list it can serve.
func (s *Store) Ready() bool { return s.ready.Load() }

// Exhausted reports whether tenantID is exhausted and why, so a plane that
// holds the store serves requests from it directly.
func (s *Store) Exhausted(tenantID string) (domain.Reason, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[tenantID]
	if !ok || !state.Exhausted() {
		return domain.ReasonNone, false
	}
	return state.Reason, true
}

// SnapshotAll lists every exhausted tenant, sorted by tenant. The list is
// sorted after the lock is released, so the request path is not held up.
func (s *Store) SnapshotAll() domain.Snapshot {
	s.mu.RLock()
	out := domain.Snapshot{AsOfVersion: s.listAsOfLocked()}
	for _, state := range s.states {
		if state.Exhausted() {
			out.Exhausted = append(out.Exhausted, state)
		}
	}
	s.mu.RUnlock()
	sort.Slice(out.Exhausted, func(i, j int) bool { return out.Exhausted[i].TenantID < out.Exhausted[j].TenantID })
	return out
}

// SnapshotTenant lists tenantID when it is exhausted.
func (s *Store) SnapshotTenant(tenantID string) domain.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := domain.Snapshot{AsOfVersion: s.listAsOfLocked()}
	if state, ok := s.states[tenantID]; ok && tenantID != "" && state.Exhausted() {
		out.Exhausted = append(out.Exhausted, state)
	}
	return out
}

// Subscribe returns a coalescing change channel and its release function.
func (s *Store) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	return ch, func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}
}

// FlushPending writes the states waiting for the cache. The store only queues
// them, so the UsageSync stream never waits on Redis; whoever runs the store
// flushes on CacheWrites, on a retry timer and once more at shutdown.
func (s *Store) FlushPending(ctx context.Context) {
	s.writer.flush(ctx)
}

// CacheWrites receives a value whenever states are queued for the cache.
func (s *Store) CacheWrites() <-chan struct{} {
	return s.writer.wake
}

// ResyncCache queues every held state again, so a cache that was flushed or
// lost writes while the store kept running is repopulated. The cache's
// version check makes rewriting what it already holds a no-op.
func (s *Store) ResyncCache() {
	s.mu.RLock()
	states := make([]domain.TenantState, 0, len(s.states))
	for _, state := range s.states {
		states = append(states, state)
	}
	s.mu.RUnlock()
	s.writer.enqueue(states)
}

func (s *Store) publish(changed []domain.TenantState) {
	if becameReady := s.markReady(); len(changed) > 0 || becameReady {
		s.notify()
	}
	s.writer.enqueue(changed)
}

// The data planes waiting for a first list are woken even when becoming ready
// changed nothing, so the caller needs to know it was this call.
func (s *Store) markReady() bool {
	return s.ready.CompareAndSwap(false, true)
}

// mergeSnapshot computes the changes under the read lock, so the request path
// keeps reading while a large list is compared, and recomputes them under the
// write lock only when another merge ran in between.
func (s *Store) mergeSnapshot(snapshot domain.Snapshot) []domain.TenantState {
	s.mu.RLock()
	generation := s.generation
	changed := snapshot.Changes(s.states)
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generation != generation {
		changed = snapshot.Changes(s.states)
	}
	s.generation++
	for _, state := range changed {
		s.states[state.TenantID] = state
		s.maxVersion = max(s.maxVersion, state.Version)
	}
	s.maxVersion = max(s.maxVersion, snapshot.AsOfVersion)
	s.snapshotAsOf = max(s.snapshotAsOf, snapshot.AsOfVersion)
	s.complete = true
	return changed
}

// listAsOfLocked is the as_of version a list carries. Until a UsageSync
// snapshot has been applied the store only holds what the cache had, which
// can miss states whose writes failed, so its lists claim nothing beyond
// what they list: a data plane then unblocks no tenant on their account.
func (s *Store) listAsOfLocked() int64 {
	if !s.complete {
		return 0
	}
	return s.maxVersion
}

func (s *Store) mergeRestored(cached []domain.TenantState) []domain.TenantState {
	s.mu.Lock()
	defer s.mu.Unlock()
	fresh := make([]domain.TenantState, 0, len(cached))
	for _, state := range cached {
		if state.Version > s.snapshotAsOf {
			fresh = append(fresh, state)
		}
	}
	return s.mergeLocked(fresh)
}

func (s *Store) merge(states []domain.TenantState) []domain.TenantState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mergeLocked(states)
}

func (s *Store) mergeLocked(states []domain.TenantState) []domain.TenantState {
	var changed []domain.TenantState
	for _, state := range states {
		if current, ok := s.states[state.TenantID]; ok && !state.Supersedes(current) {
			continue
		}
		s.states[state.TenantID] = state
		s.maxVersion = max(s.maxVersion, state.Version)
		changed = append(changed, state)
	}
	if len(changed) > 0 {
		s.generation++
	}
	return changed
}

func (s *Store) notify() {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
