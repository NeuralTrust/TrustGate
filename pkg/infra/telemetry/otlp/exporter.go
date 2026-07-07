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
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

const (
	loggerScope            = "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
	defaultShutdownTimeout = 5 * time.Second
)

var _ appmetrics.Exporter = (*Exporter)(nil)

var errExporterClosed = errors.New("otlp: exporter is closed")

// Exporter ships business events to an OTel Collector as OTLP log records
// through a dedicated, non-global LoggerProvider. It serves the metadata class by
// default and the raw class when declared under exporters.raw.
type Exporter struct {
	provider        *sdklog.LoggerProvider
	logger          otellog.Logger
	slog            *slog.Logger
	shutdownTimeout time.Duration
	class           metrics.DataClass
	closed          atomic.Bool
}

// newExporterWithProvider builds an Exporter around an already-constructed
// provider. It is the seam tests use to inject an in-memory log exporter.
func newExporterWithProvider(
	provider *sdklog.LoggerProvider,
	logger *slog.Logger,
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
		shutdownTimeout: shutdownTimeout,
	}
}

func (e *Exporter) Name() string {
	return ExporterName
}

// DataClass reports the class this exporter is bound to. It defaults to metadata
// and becomes raw when SetDataClass is called at build time.
func (e *Exporter) DataClass() metrics.DataClass {
	if e.class == metrics.Raw {
		return metrics.Raw
	}
	return metrics.Metadata
}

// SetDataClass binds the exporter to a data class before it serves traffic.
func (e *Exporter) SetDataClass(class metrics.DataClass) {
	e.class = class
}

// Publish maps the event to an OTLP log record and enqueues it without blocking
// on Collector latency. A raw-class exporter emits request/response payloads;
// other classes emit sanitized metadata. It errors only if already closed.
func (e *Exporter) Publish(ctx context.Context, evt *events.Event) error {
	if evt == nil {
		return nil
	}
	if e.closed.Load() {
		return errExporterClosed
	}
	if e.class == metrics.Raw {
		raw := evt.SensibleView()
		e.logger.Emit(ctx, rawEventToRecord(&raw))
		e.logPublished(metrics.Raw, rawEventName, &raw)
		return nil
	}
	metadata := evt.MetadataView()
	e.logger.Emit(ctx, eventToRecord(&metadata))
	e.logPublished(metrics.Metadata, eventName, &metadata)
	return nil
}

func (e *Exporter) logPublished(class metrics.DataClass, name string, evt *events.Event) {
	e.slog.Debug("otlp event published to collector",
		slog.String("exporter", ExporterName),
		slog.String("class", string(class)),
		slog.String("event", name),
		slog.Int("schema_version", evt.SchemaVersion),
		slog.String("trace_id", evt.TraceID),
		slog.String("gateway_id", evt.GatewayID),
		slog.String("team_id", evt.TeamID),
	)
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
