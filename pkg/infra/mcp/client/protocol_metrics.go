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

package client

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ProtocolDecision is a bounded southbound negotiation outcome.
type ProtocolDecision struct {
	Source   string
	Mode     string
	Era      string
	Result   string
	Category string
	Latency  time.Duration
}

// ProtocolDecisionRecorder records bounded upstream protocol decisions.
type ProtocolDecisionRecorder interface {
	Record(ctx context.Context, decision ProtocolDecision)
}

type otelProtocolDecisionRecorder struct {
	counter metric.Int64Counter
	latency metric.Float64Histogram
}

// NewProtocolDecisionRecorder returns a no-op nil recorder unless ops metrics are enabled.
func NewProtocolDecisionRecorder(enabled bool) ProtocolDecisionRecorder {
	if !enabled {
		return nil
	}
	meter := otel.Meter("trustgate/mcp_upstream")
	counter, err := meter.Int64Counter(
		"mcp.upstream.protocol.decision_total",
		metric.WithUnit("{decision}"),
	)
	if err != nil {
		return nil
	}
	latency, err := meter.Float64Histogram(
		"mcp.upstream.protocol.probe_latency_seconds",
		metric.WithUnit("s"),
	)
	if err != nil {
		return &otelProtocolDecisionRecorder{counter: counter}
	}
	return &otelProtocolDecisionRecorder{counter: counter, latency: latency}
}

func (r *otelProtocolDecisionRecorder) Record(ctx context.Context, decision ProtocolDecision) {
	if r == nil || r.counter == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("source", decision.Source),
		attribute.String("mode", decision.Mode),
		attribute.String("era", decision.Era),
		attribute.String("result", decision.Result),
	}
	if decision.Category != "" {
		attrs = append(attrs, attribute.String("category", decision.Category))
	}
	r.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
	if decision.Source != string(decisionProbe) || r.latency == nil {
		return
	}
	r.latency.Record(ctx, decision.Latency.Seconds())
}
