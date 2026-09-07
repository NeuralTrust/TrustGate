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
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func telemetryConfig(tel config.TelemetryConfig) *config.Config {
	return &config.Config{AppEnv: "test", Telemetry: tel}
}

func TestNewSDKDisabledInstallsNothing(t *testing.T) {
	sdk, err := NewSDK(telemetryConfig(config.TelemetryConfig{}), testLogger())
	require.NoError(t, err)
	require.Nil(t, sdk.Tracer())
	require.NoError(t, sdk.Shutdown(context.Background()))
}

// Enabling a signal without its endpoint must fail at boot. Starting anyway is
// how a gateway ends up exporting nothing while looking healthy (AUT-576).
func TestNewSDKRejectsTracesWithoutEndpoint(t *testing.T) {
	_, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsTracesEnabled: true,
	}), testLogger())
	require.ErrorContains(t, err, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
}

func TestNewSDKRejectsMetricsWithoutEndpoint(t *testing.T) {
	_, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsMetricsEnabled: true,
	}), testLogger())
	require.ErrorContains(t, err, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
}

func TestNewSDKTracesProvideTracer(t *testing.T) {
	// NewSDK installs a tracer provider and a propagator process-wide, so this has
	// to hand both back or every later test in the package inherits them.
	usePropagator(t, propagation.NewCompositeTextMapPropagator())
	useTracerProvider(t)

	sdk, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsTracesEnabled: true,
		OTLP:             config.OTLPConfig{TracesEndpoint: "collector.svc:4318"},
	}), testLogger())
	require.NoError(t, err)
	require.NotNil(t, sdk.Tracer())
	require.NoError(t, sdk.Shutdown(context.Background()))
}

// Installing the propagator is the load-bearing half of outbound propagation:
// without it otelhttp opens client spans and injects nothing, which is how the
// gateway stayed a separate trace root from everything it calls.
func TestNewSDKInstallsTraceContextPropagator(t *testing.T) {
	usePropagator(t, propagation.NewCompositeTextMapPropagator())
	useTracerProvider(t)

	sdk, err := NewSDK(telemetryConfig(config.TelemetryConfig{
		OpsTracesEnabled: true,
		OTLP:             config.OTLPConfig{TracesEndpoint: "collector.svc:4318"},
	}), testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sdk.Shutdown(context.Background())) })

	fields := otel.GetTextMapPropagator().Fields()
	require.Contains(t, fields, "traceparent")
	// Baggage is deliberately absent: nothing here reads or writes it, so on a
	// public edge it would be surface for no benefit.
	require.NotContains(t, fields, "baggage")
}

func TestNewSDKDisabledInstallsNoPropagator(t *testing.T) {
	usePropagator(t, propagation.NewCompositeTextMapPropagator())

	_, err := NewSDK(telemetryConfig(config.TelemetryConfig{}), testLogger())
	require.NoError(t, err)
	require.Empty(t, otel.GetTextMapPropagator().Fields())
}

func TestSignalEndpointAddsSignalPath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "bare authority", raw: "collector.svc:4318", want: "http://collector.svc:4318/v1/traces"},
		{name: "scheme only", raw: "https://collector.svc:4318", want: "https://collector.svc:4318/v1/traces"},
		{name: "trailing slash", raw: "http://collector.svc:4318/", want: "http://collector.svc:4318/v1/traces"},
		{name: "explicit path kept", raw: "http://collector.svc:4318/otlp/v1/traces", want: "http://collector.svc:4318/otlp/v1/traces"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signalEndpoint(tc.raw, tracesSignalPath, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSamplingRatioClampsOutOfRange(t *testing.T) {
	require.InDelta(t, 1.0, samplingRatio(0), 0)
	require.InDelta(t, 1.0, samplingRatio(-0.5), 0)
	require.InDelta(t, 1.0, samplingRatio(2), 0)
	require.InDelta(t, 0.25, samplingRatio(0.25), 0)
}

func TestProbeSamplingRatioAcceptsZeroAndFallsBackWhenOutOfRange(t *testing.T) {
	// 0 is the point of a separate knob: drop probe spans, keep everything else.
	// samplingRatio would turn it into 1.0 and make that impossible to express.
	require.InDelta(t, 0.0, probeSamplingRatio(0), 0)
	require.InDelta(t, 0.05, probeSamplingRatio(0.05), 0)
	// Out of range must land on the safe default, never on the main ratio. "10"
	// meaning 10% is the likely typo, and every overlay runs the main ratio at
	// 1.0, so deferring to it would answer a typo with a full probe flood.
	require.InDelta(t, fallbackProbeSamplingRatio, probeSamplingRatio(-1), 0)
	require.InDelta(t, fallbackProbeSamplingRatio, probeSamplingRatio(10), 0)
	require.Greater(t, fallbackSamplingRatio, fallbackProbeSamplingRatio)
}

// The route sampler is all that stands between a fleet of liveness probes and
// the trace store, so both directions of the split are pinned: probes must not
// borrow the main ratio, and request traffic must not borrow the probe one.
func TestRouteSamplerSplitsProbeAndRequestTraffic(t *testing.T) {
	tests := []struct {
		name       string
		ratio      float64
		probeRatio float64
		route      Route
		wantSpans  int
	}{
		{name: "probe dropped at probe ratio zero", ratio: 1, probeRatio: 0, route: RouteHealth},
		{name: "request survives while probes are dropped", ratio: 1, probeRatio: 0, route: RouteProxyForward, wantSpans: 1},
		{name: "probe kept at full probe ratio", ratio: 1, probeRatio: 1, route: RouteHealth, wantSpans: 1},
		{name: "request follows the main ratio", ratio: 0, probeRatio: 1, route: RouteProxyForward},
		{name: "probe follows the probe ratio", ratio: 0, probeRatio: 1, route: RouteHealth, wantSpans: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, recorder := sampledProvider(t, requestSampler(tc.ratio, tc.probeRatio))

			_, span := provider.StartRequestSpan(context.Background(), "GET "+string(tc.route), tc.route)
			span.Finish(SpanOutcome{Request: Request{Route: tc.route}})

			require.Len(t, recorder.Ended(), tc.wantSpans)
		})
	}
}

// A child is never re-judged by route. Without ParentBased around the route
// sampler, a sampled request trace would lose every span that happens to be
// classified as a probe, leaving a hole in the middle of the trace.
func TestRouteSamplerChildInheritsSampledParent(t *testing.T) {
	provider, recorder := sampledProvider(t, requestSampler(1, 0))

	ctx, parent := provider.StartRequestSpan(context.Background(), "POST proxy.forward", RouteProxyForward)
	_, child := provider.StartRequestSpan(ctx, "GET health", RouteHealth)
	child.Finish(SpanOutcome{})
	parent.Finish(SpanOutcome{})

	require.Len(t, recorder.Ended(), 2)
}

// ShouldSample runs before the handler, so the route only reaches the sampler if
// it is stamped at span start. Attributes added at Finish are invisible to it,
// which is why the route is a parameter rather than derived from the outcome.
func TestStartRequestSpanExposesRouteToTheSampler(t *testing.T) {
	sampler := &capturingSampler{}
	provider, _ := sampledProvider(t, sampler)

	_, span := provider.StartRequestSpan(context.Background(), "GET health", RouteHealth)
	span.Finish(SpanOutcome{})

	require.True(t, isProbeRoute(sampler.attributes))
}

func TestIsProbeRouteMatchesOnlyTheHealthRoute(t *testing.T) {
	require.False(t, isProbeRoute(nil))
	require.False(t, isProbeRoute([]attribute.KeyValue{attribute.String("plane", string(PlaneAdmin))}))
	require.False(t, isProbeRoute([]attribute.KeyValue{routeAttributeKey.String(string(RouteProxyForward))}))
	require.True(t, isProbeRoute([]attribute.KeyValue{routeAttributeKey.String(string(RouteHealth))}))
}

func sampledProvider(t *testing.T, sampler sdktrace.Sampler) (*Provider, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(recorder),
		sdktrace.WithSampler(sampler),
	)
	t.Cleanup(func() { require.NoError(t, tp.Shutdown(context.Background())) })
	return &Provider{tracer: tp.Tracer("test")}, recorder
}

// capturingSampler records the attributes ShouldSample was able to see.
type capturingSampler struct {
	attributes []attribute.KeyValue
}

func (s *capturingSampler) ShouldSample(p sdktrace.SamplingParameters) sdktrace.SamplingResult {
	s.attributes = p.Attributes
	return sdktrace.AlwaysSample().ShouldSample(p)
}

func (s *capturingSampler) Description() string { return "capturingSampler" }

func TestResourceIdentifiesTheGateway(t *testing.T) {
	attrs := map[string]string{}
	for _, kv := range newResource(telemetryConfig(config.TelemetryConfig{})).Attributes() {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}
	require.Equal(t, ServiceName, attrs["service.name"])
	require.Equal(t, ServiceName, attrs[gatewayAttribute])
	require.Equal(t, "test", attrs["deployment.environment.name"])
}
