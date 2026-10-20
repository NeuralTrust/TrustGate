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

// Package usage ships usage records over OTLP through a pipeline of their own,
// apart from the observability exporters and the telemetry toggle.
package usage

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

const (
	loggerScope     = "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/usage"
	shutdownTimeout = 10 * time.Second
)

var _ usagedomain.Emitter = (*Emitter)(nil)

// Emitter ships usage records. A disabled Emitter accepts records and does
// nothing with them.
type Emitter struct {
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
	slog     *slog.Logger
	now      func() time.Time
}

// New builds the Emitter from cfg. It is disabled unless
// cfg.UsageRecords.Enabled is set; the OTLP client connects lazily, so an
// unreachable collector never blocks construction.
func New(ctx context.Context, cfg *config.Config, outcomes usagedomain.OutcomeRecorder, logger *slog.Logger) (*Emitter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil || !cfg.UsageRecords.Enabled {
		return &Emitter{slog: logger}, nil
	}
	exporter, err := otlp.NewStandaloneLogExporter(ctx, cfg.UsageRecords.OTLP, cfg.Telemetry.OTLP)
	if err != nil {
		return nil, fmt.Errorf("usage records exporter: %w", err)
	}
	return newEmitter(exporter, cfg.UsageRecords.QueueSize, outcomes, logger), nil
}

func newEmitter(
	exporter sdklog.Exporter,
	queueSize int,
	outcomes usagedomain.OutcomeRecorder,
	logger *slog.Logger,
) *Emitter {
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(newQueueProcessor(exporter, queueSize, outcomes, logger)),
		sdklog.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(usagedomain.Product),
		)),
	)
	return &Emitter{
		provider: provider,
		logger:   provider.Logger(loggerScope),
		slog:     logger,
		now:      time.Now,
	}
}

// Enabled reports whether records are shipped.
func (e *Emitter) Enabled() bool {
	return e != nil && e.provider != nil
}

// Emit queues r for export without blocking. The record never takes the trace
// context of the caller's span: usage.trace_id is the only link to the request.
func (e *Emitter) Emit(_ context.Context, r usagedomain.Record) {
	if !e.Enabled() {
		return
	}
	e.logger.Emit(context.Background(), toLogRecord(r, e.now()))
}

// Close exports the queued records and shuts the pipeline down, bounded by a
// timeout so shutdown never hangs on an unreachable collector. Records that
// cannot be exported in time are counted as failed exports.
func (e *Emitter) Close() {
	e.closeWithin(shutdownTimeout)
}

func (e *Emitter) closeWithin(timeout time.Duration) {
	if !e.Enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := e.provider.Shutdown(ctx); err != nil {
		e.slog.Warn("usage records shutdown failed", slog.String("error", err.Error()))
	}
}
