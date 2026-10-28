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

// cacheWriter keeps the states waiting to be written to the cache, latest per
// tenant, and writes them one flush at a time, so two writes for a tenant are
// never in flight together and an older one cannot land after a newer one.
type cacheWriter struct {
	cache   domain.StateCache
	timeout time.Duration
	logger  *slog.Logger
	wake    chan struct{}

	flushMu sync.Mutex
	mu      sync.Mutex
	pending map[string]domain.TenantState
}

func newCacheWriter(cache domain.StateCache, timeout time.Duration, logger *slog.Logger) *cacheWriter {
	return &cacheWriter{
		cache:   cache,
		timeout: timeout,
		logger:  logger,
		wake:    make(chan struct{}, 1),
		pending: make(map[string]domain.TenantState),
	}
}

func (w *cacheWriter) enqueue(states []domain.TenantState) {
	if len(states) == 0 {
		return
	}
	w.put(states)
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// A chunk in flight is detached from ctx so a shutdown does not cut it, and
// bounded by timeout so a hung cache costs one chunk; what is not written goes
// back to pending unless a later enqueue superseded it.
func (w *cacheWriter) flush(ctx context.Context) {
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	batch := w.takeAll()
	for start := 0; start < len(batch); start += cacheChunk {
		if ctx.Err() != nil {
			w.put(batch[start:])
			return
		}
		chunk := batch[start:min(start+cacheChunk, len(batch))]
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.timeout)
		err := w.cache.SaveAll(writeCtx, chunk)
		cancel()
		if err != nil {
			w.put(batch[start:])
			w.logger.WarnContext(ctx, "usage: cache states, retrying later", slog.Int("states", len(batch)-start), slog.Any("error", err))
			return
		}
	}
}

func (w *cacheWriter) put(states []domain.TenantState) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, state := range states {
		if held, ok := w.pending[state.TenantID]; !ok || state.Supersedes(held) {
			w.pending[state.TenantID] = state
		}
	}
}

func (w *cacheWriter) takeAll() []domain.TenantState {
	w.mu.Lock()
	defer w.mu.Unlock()
	batch := make([]domain.TenantState, 0, len(w.pending))
	for _, state := range w.pending {
		batch = append(batch, state)
	}
	w.pending = make(map[string]domain.TenantState)
	sort.Slice(batch, func(i, j int) bool { return batch[i].TenantID < batch[j].TenantID })
	return batch
}
