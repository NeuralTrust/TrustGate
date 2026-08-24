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

// Package o11y provides bounded operational telemetry instruments.
package o11y

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Plane is a bounded AgentGateway serving plane.
type Plane string

const (
	PlaneAdmin Plane = "admin"
	PlaneProxy Plane = "proxy"
	PlaneMCP   Plane = "mcp"
)

// Route is a bounded route group that never contains path parameters.
type Route string

const (
	RouteHealth          Route = "health"
	RouteVersion         Route = "version"
	RouteAdminGateways   Route = "admin.gateways"
	RouteAdminCatalog    Route = "admin.catalog"
	RouteAdminConfigSync Route = "admin.config_sync"
	RouteAdminDocs       Route = "admin.docs"
	RouteProxyForward    Route = "proxy.forward"
	RouteMCPRPC          Route = "mcp.rpc"
	RouteMCPOAuth        Route = "mcp.oauth"
	RouteOther           Route = "other"
)

// routeAttributeKey carries the bounded Route on a span. It is stamped at span
// start as well as at Finish because the sampler reads it, and ShouldSample runs
// before the handler.
const routeAttributeKey = attribute.Key("http.route")

// Outcome is a bounded request result.
type Outcome string

const (
	OutcomeAllowed         Outcome = "allowed"
	OutcomeDeniedAuth      Outcome = "denied_auth"
	OutcomeDeniedForbidden Outcome = "denied_forbidden"
	OutcomeDeniedThrottled Outcome = "denied_throttled"
	OutcomeDeniedPolicy    Outcome = "denied_policy"
	OutcomeClientError     Outcome = "client_error"
	OutcomeServerError     Outcome = "server_error"
	OutcomeProbe           Outcome = "probe"
)

// Request is the complete, low-cardinality metric input.
type Request struct {
	Plane       Plane
	Route       Route
	Method      string
	StatusClass string
	Outcome     Outcome
	Duration    time.Duration
}

// SpanOutcome closes a server span. It carries the same bounded Request the
// metric records plus the product trace id, which belongs on a span (one value
// per request) and never on a metric attribute (unbounded cardinality).
type SpanOutcome struct {
	Request
	TraceID string
}

// RequestSpan is the server span of one in-flight request.
type RequestSpan interface {
	// Finish stamps the bounded outcome and ends the span.
	Finish(SpanOutcome)
}

// RequestRecorder records bounded operational telemetry for one request: a
// metric sample, and a server span when traces are enabled.
type RequestRecorder interface {
	Enabled() bool
	RecordRequest(context.Context, Request)
	StartRequestSpan(ctx context.Context, name string, route Route) (context.Context, RequestSpan)
}

// Provider owns the operational OTel instruments.
type Provider struct {
	metricsEnabled bool
	tracer         trace.Tracer
	duration       metric.Float64Histogram
	outcomes       metric.Int64Counter
}

// NewProvider creates the operational instruments. Instruments must be created
// after SDK installed the global MeterProvider, hence the dependency: resolving
// them earlier would bind them to the no-op provider for the process lifetime.
func NewProvider(cfg *config.Config, sdk *SDK) (*Provider, error) {
	p := &Provider{
		metricsEnabled: cfg.Telemetry.OpsMetricsEnabled,
		tracer:         sdk.Tracer(),
	}
	if !p.metricsEnabled {
		return p, nil
	}

	meter := otel.Meter(instrumentationScope)
	duration, err := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10),
	)
	if err != nil {
		return nil, err
	}
	outcomes, err := meter.Int64Counter(
		"agentgateway.request.outcome_total",
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, err
	}
	p.duration = duration
	p.outcomes = outcomes
	return p, nil
}

// Enabled reports whether any operational signal is recording, so a caller can
// skip the whole measurement path when neither metrics nor traces are on.
func (p *Provider) Enabled() bool {
	return p != nil && (p.metricsEnabled || p.tracer != nil)
}

// StartRequestSpan starts the server span for a request. The returned context
// carries the span, so downstream instrumentation can nest under it.
//
// The route is passed in rather than derived at Finish because it feeds the
// sampling decision, which is made here.
func (p *Provider) StartRequestSpan(ctx context.Context, name string, route Route) (context.Context, RequestSpan) {
	if p == nil || p.tracer == nil {
		return ctx, noopSpan{}
	}
	ctx, span := p.tracer.Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(routeAttributeKey.String(string(route))),
	)
	return ctx, otelSpan{span: span}
}

// RecordRequest records one duration sample and one outcome.
func (p *Provider) RecordRequest(ctx context.Context, req Request) {
	if p == nil || !p.metricsEnabled {
		return
	}
	// Operational metrics intentionally carry no trace/span IDs, including
	// through SDK-generated exemplars.
	ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	p.duration.Record(ctx, req.Duration.Seconds(), metric.WithAttributes(
		attribute.String("http.request.method", req.Method),
		attribute.String("http.route", string(req.Route)),
		attribute.String("http.response.status_class", req.StatusClass),
	))
	p.outcomes.Add(ctx, 1, metric.WithAttributes(
		attribute.String("plane", string(req.Plane)),
		attribute.String("route", string(req.Route)),
		attribute.String("outcome", string(req.Outcome)),
	))
}

// otelSpan adapts an OTel span to RequestSpan. Attributes mirror the metric
// dimensions on purpose: the same bounded classification, so a span and a series
// can be joined without a lookup table. The request URL is deliberately absent —
// it carries consumer paths and query strings.
type otelSpan struct {
	span trace.Span
}

func (s otelSpan) Finish(out SpanOutcome) {
	attrs := []attribute.KeyValue{
		attribute.String("http.request.method", out.Method),
		routeAttributeKey.String(string(out.Route)),
		attribute.String("http.response.status_class", out.StatusClass),
		attribute.String("plane", string(out.Plane)),
		attribute.String("outcome", string(out.Outcome)),
	}
	if out.TraceID != "" {
		attrs = append(attrs, attribute.String("trustgate.trace_id", out.TraceID))
	}
	s.span.SetAttributes(attrs...)
	if out.Outcome == OutcomeServerError {
		s.span.SetStatus(codes.Error, string(OutcomeServerError))
	}
	s.span.End()
}

// noopSpan keeps the middleware free of nil checks when traces are disabled.
type noopSpan struct{}

func (noopSpan) Finish(SpanOutcome) {}
