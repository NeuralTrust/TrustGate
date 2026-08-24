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

package complexity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// These tests drive the OTel process globals, which is what the instrumented
// transport reads, so they restore what they replace and never run in parallel.

func usePropagator(t *testing.T, p propagation.TextMapPropagator) {
	t.Helper()
	previous := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(p)
	t.Cleanup(func() { otel.SetTextMapPropagator(previous) })
}

func useTracerProvider(t *testing.T) {
	t.Helper()
	tp := sdktrace.NewTracerProvider()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		require.NoError(t, tp.Shutdown(context.Background()))
	})
}

// scoreHeaders performs one Score call against a stub firewall and reports what
// actually reached the wire.
func scoreHeaders(t *testing.T, ctx context.Context) http.Header {
	t.Helper()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		require.NoError(t, json.NewEncoder(w).Encode(scoreResponse{Score: 0.5}))
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, tokenProviderStub{configured: true, token: "secret-token"}, time.Second)
	_, err := client.Score(ctx, "hello", "chat_1", "tenant_1")
	require.NoError(t, err)
	return got
}

// The complexity call is the gateway's other internal hop, so it needs the same
// edge into firewall-gateway that the TrustGuard call gets — without disturbing
// the token header the firewall authenticates on.
func TestScoreSendsTraceContextAlongsideToken(t *testing.T) {
	usePropagator(t, propagation.TraceContext{})
	useTracerProvider(t)

	ctx, span := otel.Tracer("test").Start(context.Background(), "POST proxy.forward")
	defer span.End()
	header := scoreHeaders(t, ctx)

	require.Contains(t, header.Get("traceparent"), span.SpanContext().TraceID().String())
	require.Equal(t, "secret-token", header.Get(headerToken))
}

// With operational traces off nothing installs a tracer provider or a propagator,
// so no tracer provider is installed here either: the call must reach the firewall
// exactly as it did before instrumentation.
func TestScoreSendsNoTraceContextWhenTracesAreDisabled(t *testing.T) {
	usePropagator(t, propagation.NewCompositeTextMapPropagator())

	header := scoreHeaders(t, context.Background())

	require.Empty(t, header.Get("traceparent"))
	require.Equal(t, "secret-token", header.Get(headerToken))
}
