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

package otlp

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

const (
	loggerScope            = "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
	defaultShutdownTimeout = 5 * time.Second
)

var _ appmetrics.Exporter = (*Exporter)(nil)

var errExporterClosed = errors.New("otlp: exporter is closed")

// Exporter ships sanitized business events to an OTel Collector as OTLP log
// records through a dedicated, non-global LoggerProvider.
type Exporter struct {
	provider        *sdklog.LoggerProvider
	logger          otellog.Logger
	slog            *slog.Logger
	maxBodyBytes    int
	shutdownTimeout time.Duration
	closed          atomic.Bool
}

// newExporterWithProvider builds an Exporter around an already-constructed
// provider. It is the seam tests use to inject an in-memory log exporter.
func newExporterWithProvider(
	provider *sdklog.LoggerProvider,
	logger *slog.Logger,
	maxBodyBytes int,
	shutdownTimeout time.Duration,
) *Exporter {
	if logger == nil {
		logger = slog.Default()
	}
	if shutdownTimeout <= 0 {
		shutdownTimeout = defaultShutdownTimeout
	}
	return &Exporter{
		provider:        provider,
		logger:          provider.Logger(loggerScope),
		slog:            logger,
		maxBodyBytes:    maxBodyBytes,
		shutdownTimeout: shutdownTimeout,
	}
}

func (e *Exporter) Name() string {
	return ExporterName
}

// Publish maps the event to an OTLP log record and enqueues it into the batch
// processor without blocking on Collector latency. It returns an error only if
// the exporter has already been closed.
func (e *Exporter) Publish(ctx context.Context, evt *events.Event) error {
	if evt == nil {
		return nil
	}
	if e.closed.Load() {
		return errExporterClosed
	}
	e.logger.Emit(ctx, eventToRecord(evt, e.maxBodyBytes))
	return nil
}

// Close flushes buffered records then shuts the provider down, bounded by the
// configured timeout so shutdown can never hang.
func (e *Exporter) Close() {
	if e.provider == nil || !e.closed.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.shutdownTimeout)
	defer cancel()
	if err := e.provider.ForceFlush(ctx); err != nil {
		e.slog.Warn("otlp exporter flush failed on close", slog.String("error", err.Error()))
	}
	if err := e.provider.Shutdown(ctx); err != nil {
		e.slog.Warn("otlp exporter shutdown failed", slog.String("error", err.Error()))
	}
}
