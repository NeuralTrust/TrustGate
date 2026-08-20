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
	RouteMCPSubscription Route = "mcp.subscription"
	RouteOther           Route = "other"
)

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

// RequestRecorder records bounded operational request metrics.
type RequestRecorder interface {
	Enabled() bool
	RecordRequest(context.Context, Request)
}

// Provider owns the operational OTel instruments.
type Provider struct {
	enabled  bool
	duration metric.Float64Histogram
	outcomes metric.Int64Counter
}

// NewProvider creates the operational instruments. The provider remains a
// no-op unless OPS_METRICS_ENABLED is true.
func NewProvider(cfg *config.Config) (*Provider, error) {
	p := &Provider{enabled: cfg.Telemetry.OpsMetricsEnabled}
	if !p.enabled {
		return p, nil
	}

	meter := otel.Meter("github.com/NeuralTrust/TrustGate/operational")
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

// Enabled reports whether operational metrics are configured to record.
func (p *Provider) Enabled() bool {
	return p != nil && p.enabled
}

// RecordRequest records one duration sample and one outcome.
func (p *Provider) RecordRequest(ctx context.Context, req Request) {
	if !p.Enabled() {
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
