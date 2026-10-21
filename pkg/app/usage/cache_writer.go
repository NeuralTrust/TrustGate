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

package usage

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

// cacheChunk caps the states written in one round trip, so one slow chunk
// fails alone instead of the whole list.
const cacheChunk = 1000

// cacheWriter writes usage states to the cache behind the store. States a
// write could not store stay pending, latest version per tenant, until a later
// write or flush stores them.
type cacheWriter struct {
	cache   domain.StateCache
	timeout time.Duration
	logger  *slog.Logger

	mu      sync.Mutex
	pending map[string]domain.TenantState
}

func newCacheWriter(cache domain.StateCache, timeout time.Duration, logger *slog.Logger) *cacheWriter {
	return &cacheWriter{cache: cache, timeout: timeout, logger: logger, pending: make(map[string]domain.TenantState)}
}

// write stores changed, together with the states still pending, in chunks.
// Each chunk is detached from ctx's cancellation and bounded by timeout, so a
// shutdown still stores what was handed in. The first chunk that fails stops
// the write and leaves itself and the rest pending: a hung cache costs one
// timeout per write, not one per chunk.
func (w *cacheWriter) write(ctx context.Context, changed []domain.TenantState) {
	batch := w.take(changed)
	for start := 0; start < len(batch); start += cacheChunk {
		chunk := batch[start:min(start+cacheChunk, len(batch))]
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.timeout)
		err := w.cache.SaveAll(writeCtx, chunk)
		cancel()
		if err != nil {
			rest := batch[start:]
			w.keep(rest)
			w.logger.WarnContext(ctx, "usage: cache states, retrying later", slog.Int("states", len(rest)), slog.Any("error", err))
			return
		}
	}
}

// take returns changed merged with the pending states. On equal versions the
// state just applied wins: a snapshot's healthy record at as_of supersedes an
// exhausted state still pending at that version.
func (w *cacheWriter) take(changed []domain.TenantState) []domain.TenantState {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return changed
	}
	latest := w.pending
	w.pending = make(map[string]domain.TenantState)
	for _, state := range changed {
		if held, ok := latest[state.TenantID]; !ok || held.Version <= state.Version {
			latest[state.TenantID] = state
		}
	}
	batch := make([]domain.TenantState, 0, len(latest))
	for _, state := range latest {
		batch = append(batch, state)
	}
	sort.Slice(batch, func(i, j int) bool { return batch[i].TenantID < batch[j].TenantID })
	return batch
}

// keep puts failed states back. A state another write queued meanwhile at the
// same or a newer version was applied later, so it stays.
func (w *cacheWriter) keep(failed []domain.TenantState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, state := range failed {
		if held, ok := w.pending[state.TenantID]; !ok || held.Version < state.Version {
			w.pending[state.TenantID] = state
		}
	}
}
