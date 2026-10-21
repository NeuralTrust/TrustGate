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
	// SnapshotFor lists the exhausted tenants a data plane may see: every
	// tenant when all is true, otherwise only tenantID.
	SnapshotFor(tenantID string, all bool) domain.Snapshot
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

	mu         sync.RWMutex
	states     map[string]domain.TenantState
	maxVersion int64
	ready      atomic.Bool

	subsMu sync.Mutex
	subs   map[chan struct{}]struct{}
}

const maxRestoreBackoff = time.Minute

var (
	_ Applier = (*Store)(nil)
	_ Reader  = (*Store)(nil)
)

// NewStore builds an empty, not yet ready Store.
func NewStore(cache domain.StateCache, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		cache:  cache,
		logger: logger,
		states: make(map[string]domain.TenantState),
		subs:   make(map[chan struct{}]struct{}),
	}
}

// Apply records states, keeping the highest version per tenant, persists the
// ones that changed and wakes the subscribers. A cache failure is logged and
// does not undo the in-memory change: the cache only serves cold starts.
func (s *Store) Apply(ctx context.Context, states []domain.TenantState) error {
	changed := s.merge(states)
	becameReady := s.markReady()
	for _, state := range changed {
		if _, err := s.cache.Save(ctx, state); err != nil {
			s.logger.WarnContext(ctx, "usage: cache state", slog.String("tenant_id", state.TenantID), slog.Any("error", err))
		}
	}
	if len(changed) > 0 || becameReady {
		s.notify()
	}
	return nil
}

// ApplySnapshot records a full list of exhausted tenants. Listed tenants are
// merged as in Apply. A held exhausted tenant missing from the list becomes
// healthy at asOfVersion, unless the store holds a newer version for it, so a
// list that is behind cannot undo a newer block. asOfVersion becomes the
// watermark the store hands to the data planes.
func (s *Store) ApplySnapshot(ctx context.Context, exhausted []domain.TenantState, asOfVersion int64) error {
	changed, err := s.mergeSnapshot(exhausted, asOfVersion)
	if err != nil {
		return err
	}
	becameReady := s.markReady()
	for _, state := range changed {
		if _, err := s.cache.Save(ctx, state); err != nil {
			s.logger.WarnContext(ctx, "usage: cache state", slog.String("tenant_id", state.TenantID), slog.Any("error", err))
		}
	}
	if len(changed) > 0 || becameReady {
		s.notify()
	}
	return nil
}

// Watermark is the highest version the store has applied.
func (s *Store) Watermark() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxVersion
}

// Restore loads the cached states. The store becomes ready once it succeeds.
func (s *Store) Restore(ctx context.Context) error {
	states, err := s.cache.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("usage: load cached states: %w", err)
	}
	changed := s.merge(states)
	if becameReady := s.markReady(); len(changed) > 0 || becameReady {
		s.notify()
	}
	return nil
}

// RestoreUntilReady retries Restore, doubling the wait from interval up to
// maxRestoreBackoff, until the store is ready or ctx ends.
func (s *Store) RestoreUntilReady(ctx context.Context, interval time.Duration) {
	wait := interval
	for !s.Ready() {
		err := s.Restore(ctx)
		if err == nil {
			return
		}
		s.logger.WarnContext(ctx, "usage: restore cached states", slog.Any("error", err), slog.Duration("retry_in", wait))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, maxRestoreBackoff)
	}
}

// Ready reports whether the store holds a list it can serve.
func (s *Store) Ready() bool { return s.ready.Load() }

// SnapshotFor lists the exhausted tenants visible to one data plane.
func (s *Store) SnapshotFor(tenantID string, all bool) domain.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := domain.Snapshot{AsOfVersion: s.maxVersion}
	if all {
		for _, state := range s.states {
			if state.Exhausted() {
				out.Exhausted = append(out.Exhausted, state)
			}
		}
		sort.Slice(out.Exhausted, func(i, j int) bool { return out.Exhausted[i].TenantID < out.Exhausted[j].TenantID })
		return out
	}
	if state, ok := s.states[tenantID]; ok && state.Exhausted() {
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

// markReady flips the store to ready and reports whether it just did, so the
// data planes waiting for a first list are woken even when nothing changed.
func (s *Store) markReady() bool {
	return s.ready.CompareAndSwap(false, true)
}

func (s *Store) mergeSnapshot(exhausted []domain.TenantState, asOfVersion int64) ([]domain.TenantState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	listed := make(map[string]struct{}, len(exhausted))
	for _, state := range exhausted {
		listed[state.TenantID] = struct{}{}
	}
	changed := s.mergeLocked(exhausted)
	for tenantID, current := range s.states {
		if _, ok := listed[tenantID]; ok || !current.Exhausted() || current.Version > asOfVersion {
			continue
		}
		healthy, err := domain.NewTenantState(tenantID, domain.StatusHealthy, domain.ReasonNone, asOfVersion)
		if err != nil {
			return nil, fmt.Errorf("usage: unblock %s: %w", tenantID, err)
		}
		s.states[tenantID] = healthy
		changed = append(changed, healthy)
	}
	if asOfVersion > s.maxVersion {
		s.maxVersion = asOfVersion
	}
	return changed, nil
}

func (s *Store) merge(states []domain.TenantState) []domain.TenantState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mergeLocked(states)
}

func (s *Store) mergeLocked(states []domain.TenantState) []domain.TenantState {
	var changed []domain.TenantState
	for _, state := range states {
		if current, ok := s.states[state.TenantID]; ok && current.Version >= state.Version {
			continue
		}
		s.states[state.TenantID] = state
		if state.Version > s.maxVersion {
			s.maxVersion = state.Version
		}
		changed = append(changed, state)
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
