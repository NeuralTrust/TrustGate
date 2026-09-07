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

package o11y

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func recordingProvider(t *testing.T) (*Provider, *tracetest.SpanRecorder) {
	t.Helper()
	return sampledProvider(t, sdktrace.AlwaysSample())
}

func TestProviderEnabledFollowsEitherSignal(t *testing.T) {
	require.False(t, (&Provider{}).Enabled())
	require.True(t, (&Provider{metricsEnabled: true}).Enabled())

	traced, _ := recordingProvider(t)
	require.True(t, traced.Enabled())
}

func TestStartRequestSpanRecordsBoundedAttributes(t *testing.T) {
	provider, recorder := recordingProvider(t)

	_, span := provider.StartRequestSpan(context.Background(), "POST proxy.forward", RouteProxyForward)
	span.Finish(SpanOutcome{
		Request: Request{
			Plane:       PlaneProxy,
			Route:       RouteProxyForward,
			Method:      "POST",
			StatusClass: "2xx",
			Outcome:     OutcomeAllowed,
			Duration:    time.Second,
		},
		TraceID: "trace-1",
	})

	ended := recorder.Ended()
	require.Len(t, ended, 1)
	require.Equal(t, "POST proxy.forward", ended[0].Name())
	require.Equal(t, trace.SpanKindServer, ended[0].SpanKind())
	require.Equal(t, codes.Unset, ended[0].Status().Code)

	attrs := map[string]string{}
	for _, kv := range ended[0].Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	require.Equal(t, map[string]string{
		"http.request.method":        "POST",
		"http.route":                 string(RouteProxyForward),
		"http.response.status_class": "2xx",
		"plane":                      string(PlaneProxy),
		"outcome":                    string(OutcomeAllowed),
		"trustgate.trace_id":         "trace-1",
	}, attrs)
}

func TestStartRequestSpanMarksServerErrors(t *testing.T) {
	provider, recorder := recordingProvider(t)

	_, span := provider.StartRequestSpan(context.Background(), "GET proxy.forward", RouteProxyForward)
	span.Finish(SpanOutcome{Request: Request{Outcome: OutcomeServerError}})

	ended := recorder.Ended()
	require.Len(t, ended, 1)
	require.Equal(t, codes.Error, ended[0].Status().Code)
}

func TestStartRequestSpanWithoutTracerIsNoop(t *testing.T) {
	provider := &Provider{metricsEnabled: true}
	ctx := context.Background()

	got, span := provider.StartRequestSpan(ctx, "GET health", RouteHealth)
	require.Equal(t, ctx, got)
	span.Finish(SpanOutcome{})
}
