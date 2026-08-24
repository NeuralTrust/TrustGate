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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// These tests drive the OTel process globals, which is what the instrumented
// transport reads, so they restore what they replace and never run in parallel.

func useTraceContext(t *testing.T) {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
		if err := tp.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown tracer provider: %v", err)
		}
	})
}

func useNoPropagator(t *testing.T) {
	t.Helper()
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	t.Cleanup(func() { otel.SetTextMapPropagator(previous) })
}

// evaluateHeaders performs one Guard call against a stub TrustGuard and reports
// what actually reached the wire.
func evaluateHeaders(t *testing.T, ctx context.Context, traceID string) http.Header {
	t.Helper()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"allow"}`))
	}))
	t.Cleanup(srv.Close)

	if _, err := newClient(time.Second).Guard(
		ctx, srv.URL, "token", traceID, sampleRequest(), false,
	); err != nil {
		t.Fatalf("Guard: %v", err)
	}
	return got
}

// X-Trace-ID has to survive alongside traceparent. TrustGuard resolves its
// correlation_id from a platform-scoped X-Trace-ID before falling back to the
// trace it adopted, so losing this header would silently repoint the correlation
// the app joins TrustGate and TrustGuard on (AUT-594).
func TestGuardSendsTraceContextAlongsideTraceID(t *testing.T) {
	useTraceContext(t)

	ctx, span := otel.Tracer("test").Start(context.Background(), "POST proxy.forward")
	defer span.End()
	header := evaluateHeaders(t, ctx, "product-trace-id")

	wantTrace := span.SpanContext().TraceID().String()
	if got := header.Get("traceparent"); !strings.Contains(got, wantTrace) {
		t.Fatalf("traceparent = %q, want it to carry trace id %s", got, wantTrace)
	}
	if got := header.Get(traceIDHeader); got != "product-trace-id" {
		t.Fatalf("%s = %q, want product-trace-id", traceIDHeader, got)
	}
	if got := header.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("Authorization = %q, want the bearer token untouched", got)
	}
}

// With operational traces off nothing installs a propagator, so the evaluate call
// must be indistinguishable from before instrumentation.
func TestGuardSendsNoTraceContextWhenTracesAreDisabled(t *testing.T) {
	useNoPropagator(t)

	header := evaluateHeaders(t, context.Background(), "product-trace-id")

	if got := header.Get("traceparent"); got != "" {
		t.Fatalf("traceparent = %q, want empty when traces are disabled", got)
	}
	if got := header.Get(traceIDHeader); got != "product-trace-id" {
		t.Fatalf("%s = %q, want the product trace id regardless of traces", traceIDHeader, got)
	}
}
