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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// These tests drive process globals, because that is exactly what otelhttp reads.
// Each one installs what it needs and restores the previous value, so none of
// them may run in parallel and none may depend on test ordering.

func useTracerProvider(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		require.NoError(t, tp.Shutdown(context.Background()))
	})
	return recorder
}

func usePropagator(t *testing.T, p propagation.TextMapPropagator) {
	t.Helper()
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(p)
	t.Cleanup(func() { otel.SetTextMapPropagator(previous) })
}

func headerOfInternalCall(t *testing.T, ctx context.Context, transport http.RoundTripper) http.Header {
	t.Helper()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/evaluate", nil)
	require.NoError(t, err)
	res, err := (&http.Client{Transport: transport}).Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	return got
}

func evaluateTransport() http.RoundTripper {
	return InternalTransport("trustguard", "trustguard.evaluate")
}

// The gateway is only upstream of anything if it writes traceparent, so both
// halves of the edge are pinned: the header on the wire, and the client span that
// hangs off the server span.
func TestInternalTransportInjectsTraceContext(t *testing.T) {
	usePropagator(t, propagation.TraceContext{})
	recorder := useTracerProvider(t)

	ctx, server := otel.Tracer("test").Start(context.Background(), "POST proxy.forward",
		trace.WithSpanKind(trace.SpanKindServer))
	header := headerOfInternalCall(t, ctx, evaluateTransport())
	server.End()

	require.Contains(t, header.Get("traceparent"), server.SpanContext().TraceID().String())

	client := spanNamed(t, recorder, "POST trustguard.evaluate")
	require.Equal(t, trace.SpanKindClient, client.SpanKind())
	require.Equal(t, server.SpanContext().SpanID(), client.Parent().SpanID())
	require.Equal(t, "trustguard", attributeValue(client.Attributes(), peerServiceAttribute))
}

// otelhttp injects through the global propagator, and the SDK's default is an
// empty composite. Wrapping a transport without installing TraceContext yields a
// client span and no header at all: instrumented-looking, connecting nothing.
// This is the trap that kept the gateway a separate trace root.
func TestInternalTransportSendsNoTraceContextWithoutGlobalPropagator(t *testing.T) {
	usePropagator(t, propagation.NewCompositeTextMapPropagator())
	useTracerProvider(t)

	ctx, server := otel.Tracer("test").Start(context.Background(), "POST proxy.forward")
	header := headerOfInternalCall(t, ctx, evaluateTransport())
	server.End()

	require.Empty(t, header.Get("traceparent"))
}

// The DI container builds these clients independently of NewSDK, so a transport
// can exist before any propagator is installed. otelhttp resolves its propagator
// at construction by default, which would freeze that empty state and leave every
// internal call permanently unpropagated — the kind of failure that shows up as
// nothing at all. This pins the deliberately lazy lookup.
func TestInternalTransportResolvesThePropagatorPerRequest(t *testing.T) {
	usePropagator(t, propagation.NewCompositeTextMapPropagator())
	useTracerProvider(t)

	transport := evaluateTransport()
	otel.SetTextMapPropagator(propagation.TraceContext{})

	ctx, server := otel.Tracer("test").Start(context.Background(), "POST proxy.forward")
	header := headerOfInternalCall(t, ctx, transport)
	server.End()

	require.Contains(t, header.Get("traceparent"), server.SpanContext().TraceID().String())
}

// With operational traces off nothing installs a provider or a propagator, so the
// outbound request must be exactly what it was before instrumentation.
func TestInternalTransportIsInertWhenTracesAreDisabled(t *testing.T) {
	usePropagator(t, propagation.NewCompositeTextMapPropagator())

	header := headerOfInternalCall(t, context.Background(), evaluateTransport())

	require.Empty(t, header.Get("traceparent"))
	require.Empty(t, header.Get("tracestate"))
}

// A span name is a series in every backend. otelhttp's default formatter uses the
// request target, so the bounded label has to survive whatever path is called.
func TestInternalTransportSpanNameIgnoresTheRequestTarget(t *testing.T) {
	usePropagator(t, propagation.TraceContext{})
	recorder := useTracerProvider(t)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: InternalTransport("firewall-gateway", "firewall.complexity")}
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, srv.URL+"/v1/complexity?tenant=customer-id", nil,
	)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	span := spanNamed(t, recorder, "POST firewall.complexity")
	require.NotContains(t, span.Name(), "customer-id")
	require.NotContains(t, span.Name(), "/v1/complexity")
}

func spanNamed(t *testing.T, recorder *tracetest.SpanRecorder, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	names := make([]string, 0, len(recorder.Ended()))
	for _, span := range recorder.Ended() {
		if span.Name() == name {
			return span
		}
		names = append(names, span.Name())
	}
	t.Fatalf("no span named %q, got %v", name, names)
	return nil
}

func attributeValue(attrs []attribute.KeyValue, key string) string {
	for _, kv := range attrs {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}
