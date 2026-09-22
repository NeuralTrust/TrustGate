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

package trustguard

import (
	"context"
	"sync"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	failureReasonUnauthorized = "unauthorized"
	failureReasonTransport    = "transport"
)

var (
	instrumentsOnce    sync.Once
	evaluateFailures   metric.Int64Counter
	streamEvals        metric.Int64Counter
	streamResponses    metric.Int64Counter
	streamGuardCalls   metric.Int64Histogram
	streamAddedLatency metric.Int64Histogram
)

func initInstruments() {
	instrumentsOnce.Do(func() {
		meter := otel.Meter("trustgate/trustguard")
		if c, err := meter.Int64Counter(
			"trustguard_evaluate_failures_total",
			metric.WithDescription("TrustGuard /v1/evaluate call failures by reason"),
		); err == nil {
			evaluateFailures = c
		}
		if c, err := meter.Int64Counter(
			"trustguard_stream_evals_total",
			metric.WithDescription("Per-block TrustGuard evaluations of streamed responses by stream outcome"),
		); err == nil {
			streamEvals = c
		}
		if c, err := meter.Int64Counter(
			"trustguard_stream_responses_total",
			metric.WithDescription("Streamed responses inspected block by block, by stream outcome"),
		); err == nil {
			streamResponses = c
		}
		if h, err := meter.Int64Histogram(
			"trustguard_stream_guard_calls_per_response",
			metric.WithDescription("TrustGuard evaluate calls issued per streamed response"),
		); err == nil {
			streamGuardCalls = h
		}
		if h, err := meter.Int64Histogram(
			"trustguard_stream_added_latency_ms",
			metric.WithUnit("ms"),
			metric.WithDescription(
				"Sum over a streamed response of how long each held block waited before its first event reached the client",
			),
		); err == nil {
			streamAddedLatency = h
		}
	})
}

func recordEvaluateFailure(ctx context.Context, reason string) {
	initInstruments()
	if evaluateFailures == nil {
		return
	}
	evaluateFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

// recordStreamEvals publishes one streamed response, from the entry the
// executor designated to speak for the whole stream. Every instrument here is
// keyed on the response rather than on the policy, so recording it once per
// entry would count a single response once per streaming policy in the chain.
//
// The response counter is not derivable from the eval counter: skipped is
// defined as no evals at all, so its share of trustguard_stream_evals_total is
// zero by construction and only a count of responses can answer how many
// streams were never inspected.
func recordStreamEvals(ctx context.Context, r appplugins.StreamReport) {
	initInstruments()
	outcome := metric.WithAttributes(attribute.String("outcome", streamOutcomeLabel(r)))
	if streamEvals != nil {
		streamEvals.Add(ctx, int64(r.Evals), outcome)
	}
	if streamResponses != nil {
		streamResponses.Add(ctx, 1, outcome)
	}
	if streamGuardCalls != nil {
		streamGuardCalls.Record(ctx, int64(r.GuardCalls))
	}
	if streamAddedLatency != nil {
		streamAddedLatency.Record(ctx, r.AddedLatency.Milliseconds())
	}
}
