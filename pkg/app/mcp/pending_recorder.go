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

package mcp

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

const (
	pendingRecordTimeout = 5 * time.Second
	pendingQueueSize     = 256
	pendingDedupeTTL     = 10 * time.Minute
	// dedupeSweepAt is how many remembered keys trigger a sweep of expired ones.
	dedupeSweepAt = 4096
)

// PendingToolRecorder persists tool definitions a pinned registry listed that
// have no decision yet. Implementations must be idempotent: another pod, or this
// one after its dedupe window, may report the same candidate again.
type PendingToolRecorder interface {
	Record(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate) error
}

type pendingKey struct {
	registry    ids.RegistryID
	name        string
	fingerprint string
}

type pendingBatch struct {
	gatewayID  ids.GatewayID
	registryID ids.RegistryID
	tools      []registrydomain.ToolCandidate
}

// AsyncPendingRecorder takes recording off the request path. Submit only filters
// through a per-pod dedupe set and enqueues; one worker drains the queue and
// calls the inner recorder, each call bounded by pendingRecordTimeout on a
// context that is detached from any request and cancelled by Close.
//
// A full queue drops the batch (counted) and forgets its keys, so the next
// discovery offers them again. A failed Record forgets its keys too, so it is
// retried. A remembered key is not re-sent for pendingDedupeTTL, which is what
// keeps the non-cacheable discovery path and many per-principal cache keys from
// re-sending the same candidates on every call.
//
// All methods are safe on a nil receiver: Submit and Close do nothing.
type AsyncPendingRecorder struct {
	inner  PendingToolRecorder
	logger *slog.Logger
	queue  chan pendingBatch
	now    func() time.Time

	mu   sync.Mutex
	seen map[pendingKey]time.Time
	// outstanding counts batches queued or being recorded; tests use it to wait.
	outstanding atomic.Int64
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	dropped     metric.Int64Counter
	recordErr   metric.Int64Counter
}

var _ PendingToolSink = (*AsyncPendingRecorder)(nil)

// RecorderOption tunes NewAsyncPendingRecorder.
type RecorderOption func(*AsyncPendingRecorder)

// WithRecorderQueueSize sets how many batches may wait for the worker.
func WithRecorderQueueSize(n int) RecorderOption {
	return func(r *AsyncPendingRecorder) {
		if n > 0 {
			r.queue = make(chan pendingBatch, n)
		}
	}
}

// WithRecorderMeterProvider sets where the recorder's counters are created.
func WithRecorderMeterProvider(p metric.MeterProvider) RecorderOption {
	return func(r *AsyncPendingRecorder) { r.initMetrics(p) }
}

// WithRecorderClock replaces the clock the dedupe window reads.
func WithRecorderClock(now func() time.Time) RecorderOption {
	return func(r *AsyncPendingRecorder) { r.now = now }
}

// NewAsyncPendingRecorder starts the worker. Call Close on shutdown.
func NewAsyncPendingRecorder(inner PendingToolRecorder, logger *slog.Logger, opts ...RecorderOption) *AsyncPendingRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	r := &AsyncPendingRecorder{
		inner:  inner,
		logger: logger,
		queue:  make(chan pendingBatch, pendingQueueSize),
		now:    time.Now,
		seen:   make(map[pendingKey]time.Time),
	}
	r.initMetrics(otel.GetMeterProvider())
	for _, opt := range opts {
		opt(r)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.wg.Add(1)
	go r.run()
	return r
}

// initMetrics creates the counters once per recorder, never per call. A failed
// creation leaves no-op instruments: metrics never reach the request path.
func (r *AsyncPendingRecorder) initMetrics(p metric.MeterProvider) {
	meter := p.Meter("trustgate/mcp")
	var err error
	if r.dropped, err = meter.Int64Counter("trustgate.mcp.pinned_tools.dropped",
		metric.WithDescription("batches of pending tools dropped because the recorder queue was full")); err != nil {
		r.dropped = noop.Int64Counter{}
	}
	if r.recordErr, err = meter.Int64Counter("trustgate.mcp.pinned_tools.record_errors",
		metric.WithDescription("batches of pending tools the recorder failed to persist")); err != nil {
		r.recordErr = noop.Int64Counter{}
	}
}

// Submit queues the candidates this pod has not reported within the dedupe
// window. It never blocks.
func (r *AsyncPendingRecorder) Submit(gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate) {
	if r == nil || len(tools) == 0 {
		return
	}
	fresh := r.reserve(registryID, tools)
	if len(fresh) == 0 {
		return
	}
	batch := pendingBatch{gatewayID: gatewayID, registryID: registryID, tools: fresh}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		r.forget(registryID, fresh)
		return
	}
	r.outstanding.Add(1)
	select {
	case r.queue <- batch:
		r.mu.Unlock()
	default:
		r.outstanding.Add(-1)
		r.mu.Unlock()
		r.forget(registryID, fresh)
		r.dropped.Add(context.Background(), 1)
		r.logger.Warn("mcp pending tools: recorder queue full; dropping batch, it is offered again on the next discovery",
			"registry_id", registryID.String(), "tools", len(fresh))
	}
}

func (r *AsyncPendingRecorder) reserve(registryID ids.RegistryID, tools []registrydomain.ToolCandidate) []registrydomain.ToolCandidate {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) >= dedupeSweepAt {
		for k, until := range r.seen {
			if !now.Before(until) {
				delete(r.seen, k)
			}
		}
	}
	fresh := make([]registrydomain.ToolCandidate, 0, len(tools))
	for _, t := range tools {
		key := pendingKey{registryID, t.Name, t.Fingerprint}
		if until, ok := r.seen[key]; ok && now.Before(until) {
			continue
		}
		r.seen[key] = now.Add(pendingDedupeTTL)
		fresh = append(fresh, t)
	}
	return fresh
}

func (r *AsyncPendingRecorder) forget(registryID ids.RegistryID, tools []registrydomain.ToolCandidate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range tools {
		delete(r.seen, pendingKey{registryID, t.Name, t.Fingerprint})
	}
}

func (r *AsyncPendingRecorder) run() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case batch := <-r.queue:
			r.record(batch)
		}
	}
}

func (r *AsyncPendingRecorder) record(batch pendingBatch) {
	defer r.outstanding.Add(-1)
	ctx, cancel := context.WithTimeout(r.ctx, pendingRecordTimeout)
	defer cancel()
	if err := r.inner.Record(ctx, batch.gatewayID, batch.registryID, batch.tools); err != nil {
		r.forget(batch.registryID, batch.tools)
		r.recordErr.Add(context.Background(), 1)
		r.logger.Warn("mcp pending tools: failed to record; they stay hidden and are offered again on the next discovery",
			"registry_id", batch.registryID.String(), "tools", len(batch.tools), "error", err)
	}
}

// idle reports that nothing is queued or being recorded.
func (r *AsyncPendingRecorder) idle() bool { return r.outstanding.Load() == 0 }

// Close stops the worker: the in-flight Record is cancelled and queued batches
// are discarded. Pending tools are re-reported by the next discovery on any pod,
// so nothing is lost by not draining.
func (r *AsyncPendingRecorder) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}
