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
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
)

// Code Mode's metrics: how programs end, how long they run and how many
// calls they make. Labels are bounded (surface, tool, result), never a
// program, a tool it called, a gateway or a person.
const (
	programsMetric        = "trustgate.mcp.code.programs"
	programDurationMetric = "trustgate.mcp.code.program_duration"
	programCallsMetric    = "trustgate.mcp.code.program_calls"
	programReadMetric     = "trustgate.mcp.code.bytes_read"
	programReturnedMetric = "trustgate.mcp.code.bytes_returned"
)

// Results of a program beyond jsrun's error kinds (thrown, timeout, compute,
// memory, call_limit, output_limit, code_limit, stalled, crashed, busy).
const (
	programResultOK         = "ok"
	programResultAborted    = "aborted"
	programResultInvalid    = "invalid"
	programResultNotOffered = "not_offered"
)

type programMetrics struct {
	programs metric.Int64Counter
	duration metric.Float64Histogram
	calls    metric.Int64Histogram
	// read and returned are what programs' calls handed them and what they
	// handed back to clients; the difference stayed out of models' context.
	read     metric.Int64Counter
	returned metric.Int64Counter
}

func newProgramMetrics(meter metric.Meter) *programMetrics {
	if meter == nil {
		meter = otel.Meter(searchMeterName)
	}
	fallback := noop.NewMeterProvider().Meter(searchMeterName)
	warn := func(name string, err error) {
		slog.Warn("failed to create MCP Code Mode metric", slog.String("metric", name), slog.String("error", err.Error()))
	}
	programs, err := meter.Int64Counter(programsMetric, metric.WithUnit("{program}"),
		metric.WithDescription("Code Mode programs, by surface, tool (trustgate_query or trustgate_execute) and how they ended"))
	if err != nil {
		warn(programsMetric, err)
		programs, _ = fallback.Int64Counter(programsMetric)
	}
	duration, err := meter.Float64Histogram(programDurationMetric, metric.WithUnit("s"),
		metric.WithDescription("how long a Code Mode program ran, its tool calls included, by surface and tool"))
	if err != nil {
		warn(programDurationMetric, err)
		duration, _ = fallback.Float64Histogram(programDurationMetric)
	}
	calls, err := meter.Int64Histogram(programCallsMetric, metric.WithUnit("{call}"),
		metric.WithDescription("tool calls one Code Mode program made, by surface and tool"),
		metric.WithExplicitBucketBoundaries(0, 1, 2, 3, 5, 10, 20, 50))
	if err != nil {
		warn(programCallsMetric, err)
		calls, _ = fallback.Int64Histogram(programCallsMetric)
	}
	read, err := meter.Int64Counter(programReadMetric, metric.WithUnit("By"),
		metric.WithDescription("bytes Code Mode programs' tool calls handed them, by surface and tool"))
	if err != nil {
		warn(programReadMetric, err)
		read, _ = fallback.Int64Counter(programReadMetric)
	}
	returned, err := meter.Int64Counter(programReturnedMetric, metric.WithUnit("By"),
		metric.WithDescription("bytes Code Mode programs handed back to clients, by surface and tool"))
	if err != nil {
		warn(programReturnedMetric, err)
		returned, _ = fallback.Int64Counter(programReturnedMetric)
	}
	return &programMetrics{programs: programs, duration: duration, calls: calls, read: read, returned: returned}
}

func (m *programMetrics) ran(ctx context.Context, rc *appconsumer.RoutableConsumer, tool, result string, calls int) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(surfaceLabel(rc), attribute.String("tool", tool))
	m.programs.Add(ctx, 1, metric.WithAttributes(surfaceLabel(rc), attribute.String("tool", tool), attribute.String("result", result)))
	if result != programResultNotOffered && result != programResultInvalid {
		m.calls.Record(ctx, int64(calls), attrs)
	}
}

func (m *programMetrics) took(ctx context.Context, rc *appconsumer.RoutableConsumer, tool string, d time.Duration) {
	if m == nil {
		return
	}
	m.duration.Record(ctx, d.Seconds(), metric.WithAttributes(surfaceLabel(rc), attribute.String("tool", tool)))
}

func (m *programMetrics) moved(ctx context.Context, rc *appconsumer.RoutableConsumer, tool string, read, returned int64) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(surfaceLabel(rc), attribute.String("tool", tool))
	m.read.Add(ctx, read, attrs)
	m.returned.Add(ctx, returned, attrs)
}
