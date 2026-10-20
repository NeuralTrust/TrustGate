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
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

const (
	defaultBatchSize     = 512
	defaultFlushInterval = time.Second
	exportTimeout        = 30 * time.Second
	dropLogEvery         = 1000
)

var _ sdklog.Processor = (*queueProcessor)(nil)

// queueProcessor sits between the logger and the OTLP exporter in place of the
// SDK batch processor, which drops the oldest records silently when its queue
// is full. Here a full queue drops the new record and counts it, and a failed
// export is counted too, so every record ends in exactly one outcome.
type queueProcessor struct {
	exporter  sdklog.Exporter
	outcomes  usagedomain.OutcomeRecorder
	logger    *slog.Logger
	batchSize int
	interval  time.Duration
	dropped   atomic.Int64

	mu      sync.RWMutex
	closed  bool
	queue   chan sdklog.Record
	flushes chan chan struct{}
	stop    chan context.Context
	stopped chan struct{}
}

func newQueueProcessor(
	exporter sdklog.Exporter,
	queueSize int,
	outcomes usagedomain.OutcomeRecorder,
	logger *slog.Logger,
) *queueProcessor {
	p := &queueProcessor{
		exporter:  exporter,
		outcomes:  outcomes,
		logger:    logger,
		batchSize: defaultBatchSize,
		interval:  defaultFlushInterval,
		queue:     make(chan sdklog.Record, queueSize),
		flushes:   make(chan chan struct{}),
		stop:      make(chan context.Context, 1),
		stopped:   make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *queueProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool {
	return true
}

func (p *queueProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.drop("closed")
		return nil
	}
	select {
	case p.queue <- r.Clone():
	default:
		p.drop("queue_full")
	}
	return nil
}

func (p *queueProcessor) drop(reason string) {
	p.outcomes.Outcome(usagedomain.OutcomeDropped, 1)
	if n := p.dropped.Add(1); n == 1 || n%dropLogEvery == 0 {
		p.logger.Warn("usage records dropped",
			slog.String("reason", reason),
			slog.Int64("dropped_total", n),
			slog.Int("queue_size", cap(p.queue)))
	}
}

func (p *queueProcessor) ForceFlush(ctx context.Context) error {
	reply := make(chan struct{})
	select {
	case p.flushes <- reply:
	case <-p.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-reply:
	case <-ctx.Done():
		return ctx.Err()
	}
	return p.exporter.ForceFlush(ctx)
}

func (p *queueProcessor) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.stop <- ctx
	p.mu.Unlock()

	select {
	case <-p.stopped:
	case <-ctx.Done():
	}
	return errors.Join(ctx.Err(), p.exporter.Shutdown(ctx))
}

func (p *queueProcessor) run() {
	defer close(p.stopped)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	batch := make([]sdklog.Record, 0, p.batchSize)
	for {
		select {
		case r := <-p.queue:
			batch = append(batch, r)
			if len(batch) >= p.batchSize {
				batch = p.export(context.Background(), batch)
			}
		case <-ticker.C:
			batch = p.export(context.Background(), batch)
		case reply := <-p.flushes:
			batch = p.drain(context.Background(), batch)
			close(reply)
		case ctx := <-p.stop:
			p.drain(ctx, batch)
			return
		}
	}
}

func (p *queueProcessor) drain(ctx context.Context, batch []sdklog.Record) []sdklog.Record {
	for {
		select {
		case r := <-p.queue:
			batch = append(batch, r)
			if len(batch) >= p.batchSize {
				batch = p.export(ctx, batch)
			}
		default:
			return p.export(ctx, batch)
		}
	}
}

func (p *queueProcessor) export(ctx context.Context, batch []sdklog.Record) []sdklog.Record {
	if len(batch) == 0 {
		return batch
	}
	ctx, cancel := context.WithTimeout(ctx, exportTimeout)
	defer cancel()
	if err := p.exporter.Export(ctx, batch); err != nil {
		p.outcomes.Outcome(usagedomain.OutcomeExportFailed, len(batch))
		p.logger.Warn("usage records export failed",
			slog.Int("records", len(batch)),
			slog.String("error", err.Error()))
	} else {
		p.outcomes.Outcome(usagedomain.OutcomeEmitted, len(batch))
	}
	clear(batch)
	return batch[:0]
}
