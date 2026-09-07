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

package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Requests from this pool leave for OpenAI, Anthropic, Bedrock and whatever else a
// consumer configures. Our trace identity must not ride along, so this asserts the
// pool stays uninstrumented even with the gateway's own propagator installed and a
// live span on the context — the state in which a stray otelhttp wrapper would
// start leaking. It is a guard rail, not a description of behaviour worth having.
func TestPoolClientsNeverPropagateTraceContext(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	previousProvider := otel.GetTracerProvider()
	previousPropagator := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
		require.NoError(t, tp.Shutdown(context.Background()))
	})

	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	t.Cleanup(srv.Close)

	ctx, span := otel.Tracer("test").Start(context.Background(), "POST proxy.forward")
	defer span.End()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions", nil)
	require.NoError(t, err)
	res, err := NewHTTPClientPool().Get("openai", time.Second).Do(req)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	require.Empty(t, got.Get("traceparent"))
	require.Empty(t, got.Get("tracestate"))
}
