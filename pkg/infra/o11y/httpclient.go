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

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// peerServiceAttribute names the callee on a client span. It must match that
// service's own service.name or the edge is missing from the service map.
const peerServiceAttribute = "peer.service"

// InternalTransport instruments an HTTP client that calls another NeuralTrust
// service: it opens a client span and writes W3C trace context, which is what
// makes the gateway appear upstream of that service rather than each side
// showing up as its own disconnected trace root.
//
// Internal callees only. Anything that reaches a third party must stay
// uninstrumented, because those requests carry our trace identity to someone who
// has no business holding it and their URLs come from consumer configuration.
// That covers the LLM provider pool in pkg/infra/providers and also the
// openaimoderation and azurecontentsafety plugin clients.
//
// The wrapper is inert until NewSDK installs a tracer provider and a propagator,
// so with OPS_TRACES_ENABLED unset the outbound request is byte-for-byte what it
// was before. It also wraps http.DefaultTransport, which is what these clients
// already used, so connection pooling is unchanged.
//
// spanName is supplied by the caller rather than derived from the request because
// a span name is a series in every trace backend. otelhttp's default formatter
// would put the request target there, which is the one thing the repo's bounded
// route enums exist to prevent.
func InternalTransport(peerService, spanName string) http.RoundTripper {
	return otelhttp.NewTransport(
		http.DefaultTransport,
		otelhttp.WithPropagators(globalPropagator{}),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + spanName
		}),
		otelhttp.WithSpanOptions(trace.WithAttributes(
			attribute.String(peerServiceAttribute, peerService),
		)),
	)
}

// globalPropagator reads the process propagator on every call instead of once.
//
// otelhttp resolves its propagator when the transport is built. These clients are
// built by the DI container, which gives no ordering guarantee against NewSDK, so
// a transport constructed first would freeze whatever was installed at that
// moment. It happens to survive that today only because the SDK back-fills its
// global delegate exactly once per process — an invariant nothing here can see or
// enforce, protecting the one thing whose failure is silent: traces that simply
// never connect.
//
// Resolving per call costs an atomic load and makes construction order irrelevant.
type globalPropagator struct{}

func (globalPropagator) Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

func (globalPropagator) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

func (globalPropagator) Fields() []string {
	return otel.GetTextMapPropagator().Fields()
}
