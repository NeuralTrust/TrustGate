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

package mcp

import (
	"context"
	"encoding/json"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ValidationClass is a bounded northbound protocol rejection label.
type ValidationClass string

const (
	ValidationClassHeaderMismatch     ValidationClass = "header_mismatch"
	ValidationClassUnsupportedVersion ValidationClass = "unsupported_version"
	ValidationClassAcceptanceDenied   ValidationClass = "acceptance_denied"
	ValidationClassInvalidRequest     ValidationClass = "invalid_request"
	ValidationClassInvalidParams      ValidationClass = "invalid_params"
	ValidationClassParseError         ValidationClass = "parse_error"
	ValidationClassMethodNotFound     ValidationClass = "method_not_found"
)

// ProtocolValidationRecorder records bounded protocol HTTP 400 outcomes.
type ProtocolValidationRecorder interface {
	Record(ctx context.Context, class ValidationClass, era string)
}

type otelProtocolValidationRecorder struct {
	counter metric.Int64Counter
}

// AppsRecorder records bounded Apps enforcement outcomes.
type AppsRecorder interface {
	Record(ctx context.Context, operation, outcome string, count int64)
}

type otelAppsRecorder struct {
	counter metric.Int64Counter
}

// NewAppsRecorder returns metadata-only Apps enforcement telemetry.
func NewAppsRecorder(enabled bool) AppsRecorder {
	if !enabled {
		return nil
	}
	counter, err := otel.Meter("trustgate/mcp_northbound").Int64Counter(
		"mcp.northbound.apps.outcome_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	return &otelAppsRecorder{counter: counter}
}

func (r *otelAppsRecorder) Record(ctx context.Context, operation, outcome string, count int64) {
	if r == nil || r.counter == nil || count < 1 {
		return
	}
	switch operation {
	case "tools_list", "resources_list", "templates_list", "read", "call":
	default:
		return
	}
	switch outcome {
	case "dropped", "rejected":
	default:
		return
	}
	r.counter.Add(ctx, count, metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("outcome", outcome),
	))
}

// NewProtocolValidationRecorder returns a no-op nil recorder unless ops metrics are enabled.
func NewProtocolValidationRecorder(enabled bool) ProtocolValidationRecorder {
	if !enabled {
		return nil
	}
	counter, err := otel.Meter("trustgate/mcp_northbound").Int64Counter(
		"mcp.northbound.protocol.validation_total",
		metric.WithUnit("{failure}"),
	)
	if err != nil {
		return nil
	}
	return &otelProtocolValidationRecorder{counter: counter}
}

func (r *otelProtocolValidationRecorder) Record(ctx context.Context, class ValidationClass, era string) {
	if r == nil || r.counter == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("validation_class", string(class)),
	}
	if era != "" {
		attrs = append(attrs, attribute.String("era", era))
	}
	r.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// MRTROutcome is a bounded multi round-trip mediation outcome label.
type MRTROutcome string

const (
	MRTROutcomeInputRequired  MRTROutcome = trace.MRTROutcomeInputRequired
	MRTROutcomeComplete       MRTROutcome = trace.MRTROutcomeComplete
	MRTROutcomeCancelled      MRTROutcome = trace.MRTROutcomeCancelled
	MRTROutcomePolicyDenied   MRTROutcome = trace.MRTROutcomePolicyDenied
	MRTROutcomeTimeout        MRTROutcome = trace.MRTROutcomeTimeout
	MRTROutcomeRoundLimit     MRTROutcome = trace.MRTROutcomeRoundLimit
	MRTROutcomeReplayRejected MRTROutcome = trace.MRTROutcomeReplayRejected
)

// MRTRRecorder records bounded multi round-trip outcomes.
type MRTRRecorder interface {
	Record(ctx context.Context, outcome MRTROutcome, era, round string)
}

type otelMRTRRecorder struct {
	counter metric.Int64Counter
}

// NewMRTRRecorder returns a no-op nil recorder unless ops metrics are enabled.
func NewMRTRRecorder(enabled bool) MRTRRecorder {
	if !enabled {
		return nil
	}
	counter, err := otel.Meter("trustgate/mcp_northbound").Int64Counter(
		"mcp.northbound.mrtr.outcome_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	return &otelMRTRRecorder{counter: counter}
}

func (r *otelMRTRRecorder) Record(ctx context.Context, outcome MRTROutcome, era, round string) {
	if r == nil || r.counter == nil {
		return
	}
	if trace.BoundMRTROutcome(string(outcome)) == "" {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("outcome", string(outcome))}
	if era != "" {
		attrs = append(attrs, attribute.String("era", era))
	}
	if bounded := trace.BoundMRTRRoundLabel(round); bounded != "" {
		attrs = append(attrs, attribute.String("round", bounded))
	}
	r.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// TasksRecorder records bounded tasks-extension mediation outcomes.
type TasksRecorder interface {
	Record(ctx context.Context, operation, outcome, era string)
}

type otelTasksRecorder struct {
	counter metric.Int64Counter
}

// NewTasksRecorder returns a no-op nil recorder unless ops metrics are enabled.
func NewTasksRecorder(enabled bool) TasksRecorder {
	if !enabled {
		return nil
	}
	counter, err := otel.Meter("trustgate/mcp_northbound").Int64Counter(
		"mcp.northbound.tasks.outcome_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	return &otelTasksRecorder{counter: counter}
}

func (r *otelTasksRecorder) Record(ctx context.Context, operation, outcome, era string) {
	if r == nil || r.counter == nil {
		return
	}
	boundedOperation := trace.BoundTaskOperationLabel(operation)
	boundedOutcome := trace.BoundTaskOutcome(outcome)
	if boundedOperation == "" || boundedOutcome == "" {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("operation", boundedOperation),
		attribute.String("outcome", boundedOutcome),
	}
	if era != "" {
		attrs = append(attrs, attribute.String("era", era))
	}
	r.counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// SubscriptionsRecorder records bounded subscription lease telemetry: one sample
// per lifecycle event, plus a live-stream up/down counter.
type SubscriptionsRecorder interface {
	// Record counts one lease lifecycle event. kind is set only for an emitted
	// notification and is omitted from the label set otherwise.
	Record(ctx context.Context, kind, outcome, era string)
	// Live moves the live-stream counter, +1 when a lease is claimed and -1 when
	// its writer releases it.
	Live(ctx context.Context, delta int64, era string)
}

type otelSubscriptionsRecorder struct {
	outcomes metric.Int64Counter
	live     metric.Int64UpDownCounter
}

// NewSubscriptionsRecorder returns a no-op nil recorder unless ops metrics are enabled.
func NewSubscriptionsRecorder(enabled bool) SubscriptionsRecorder {
	if !enabled {
		return nil
	}
	meter := otel.Meter("trustgate/mcp_northbound")
	outcomes, err := meter.Int64Counter(
		"mcp.northbound.subscriptions.outcome_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	live, err := meter.Int64UpDownCounter(
		"mcp.northbound.subscriptions.live",
		metric.WithUnit("{stream}"),
	)
	if err != nil {
		return nil
	}
	return &otelSubscriptionsRecorder{outcomes: outcomes, live: live}
}

func (r *otelSubscriptionsRecorder) Record(ctx context.Context, kind, outcome, era string) {
	if r == nil || r.outcomes == nil {
		return
	}
	boundedOutcome := trace.BoundSubscriptionOutcome(outcome)
	if boundedOutcome == "" {
		return
	}
	attrs := []attribute.KeyValue{attribute.String("outcome", boundedOutcome)}
	if bounded := trace.BoundSubscriptionKind(kind); bounded != "" {
		attrs = append(attrs, attribute.String("kind", bounded))
	}
	if era != "" {
		attrs = append(attrs, attribute.String("era", era))
	}
	r.outcomes.Add(ctx, 1, metric.WithAttributes(attrs...))
}

func (r *otelSubscriptionsRecorder) Live(ctx context.Context, delta int64, era string) {
	if r == nil || r.live == nil || delta == 0 {
		return
	}
	var attrs []attribute.KeyValue
	if era != "" {
		attrs = append(attrs, attribute.String("era", era))
	}
	r.live.Add(ctx, delta, metric.WithAttributes(attrs...))
}

type otelSubscriptionSourceRecorder struct {
	live      metric.Int64UpDownCounter
	lifecycle metric.Int64Counter
	fanOut    metric.Int64Counter
	reconnect metric.Int64Counter
	queue     metric.Int64Counter
	terminal  metric.Int64Counter
}

// NewSubscriptionSourceRecorder returns bounded physical-listener telemetry.
func NewSubscriptionSourceRecorder(enabled bool) appmcp.SubscriptionSourceRecorder {
	if !enabled {
		return nil
	}
	meter := otel.Meter("trustgate/mcp_upstream")
	live, err := meter.Int64UpDownCounter(
		"mcp.upstream.subscriptions.listeners.live",
		metric.WithUnit("{listener}"),
	)
	if err != nil {
		return nil
	}
	lifecycle, err := meter.Int64Counter(
		"mcp.upstream.subscriptions.listener.lifecycle_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	fanOut, err := meter.Int64Counter(
		"mcp.upstream.subscriptions.fanout_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	reconnect, err := meter.Int64Counter(
		"mcp.upstream.subscriptions.reconnect_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	queue, err := meter.Int64Counter(
		"mcp.upstream.subscriptions.queue_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	terminal, err := meter.Int64Counter(
		"mcp.upstream.subscriptions.listener.terminal_total",
		metric.WithUnit("{outcome}"),
	)
	if err != nil {
		return nil
	}
	return &otelSubscriptionSourceRecorder{
		live:      live,
		lifecycle: lifecycle,
		fanOut:    fanOut,
		reconnect: reconnect,
		queue:     queue,
		terminal:  terminal,
	}
}

func (r *otelSubscriptionSourceRecorder) ListenerLive(ctx context.Context, delta int64) {
	if r == nil || r.live == nil || delta == 0 {
		return
	}
	r.live.Add(ctx, delta)
}

func (r *otelSubscriptionSourceRecorder) Lifecycle(ctx context.Context, outcome string) {
	if r == nil || r.lifecycle == nil {
		return
	}
	if bounded := trace.BoundSubscriptionSourceLifecycleOutcome(outcome); bounded != "" {
		r.lifecycle.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", bounded)))
	}
}

func (r *otelSubscriptionSourceRecorder) FanOut(
	ctx context.Context,
	kind appmcp.NotificationKind,
	outcome string,
) {
	if r == nil || r.fanOut == nil {
		return
	}
	boundedKind := trace.BoundSubscriptionKind(string(kind))
	boundedOutcome := trace.BoundSubscriptionSourceFanOutOutcome(outcome)
	if boundedKind == "" || boundedOutcome == "" {
		return
	}
	r.fanOut.Add(ctx, 1, metric.WithAttributes(
		attribute.String("kind", boundedKind),
		attribute.String("outcome", boundedOutcome),
	))
}

func (r *otelSubscriptionSourceRecorder) Reconnect(ctx context.Context, outcome string) {
	if r == nil || r.reconnect == nil {
		return
	}
	if bounded := trace.BoundSubscriptionSourceReconnectOutcome(outcome); bounded != "" {
		r.reconnect.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", bounded)))
	}
}

func (r *otelSubscriptionSourceRecorder) Queue(
	ctx context.Context,
	kind appmcp.NotificationKind,
	outcome string,
) {
	if r == nil || r.queue == nil {
		return
	}
	boundedKind := trace.BoundSubscriptionKind(string(kind))
	boundedOutcome := trace.BoundSubscriptionSourceQueueOutcome(outcome)
	if boundedKind == "" || boundedOutcome == "" {
		return
	}
	r.queue.Add(ctx, 1, metric.WithAttributes(
		attribute.String("kind", boundedKind),
		attribute.String("outcome", boundedOutcome),
	))
}

func (r *otelSubscriptionSourceRecorder) Terminal(ctx context.Context, outcome string) {
	if r == nil || r.terminal == nil {
		return
	}
	if bounded := trace.BoundSubscriptionSourceTerminalOutcome(outcome); bounded != "" {
		r.terminal.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", bounded)))
	}
}

type mcpProtocolContextKey struct{}

type mcpProtocolAttrs struct {
	era     string
	version string
}

func withMCPProtocol(ctx context.Context, era protocolEra, version string) context.Context {
	return context.WithValue(ctx, mcpProtocolContextKey{}, mcpProtocolAttrs{
		era:     eraLabel(era),
		version: trace.BoundMCPProtocolVersion(version),
	})
}

func stampMCPProtocol(span *trace.Span, ctx context.Context) {
	if span == nil {
		return
	}
	attrs, ok := ctx.Value(mcpProtocolContextKey{}).(mcpProtocolAttrs)
	if !ok {
		return
	}
	span.SetMCPProtocol(attrs.era, attrs.version)
}

func eraLabel(era protocolEra) string {
	if era == protocolEraModern {
		return trace.MCPProtocolEraModern
	}
	return trace.MCPProtocolEraLegacy
}

func validationClassForCode(code int) (ValidationClass, bool) {
	switch code {
	case codeHeaderMismatch:
		return ValidationClassHeaderMismatch, true
	case codeAcceptanceDenied:
		return ValidationClassAcceptanceDenied, true
	case codeUnsupportedProtocolVersion:
		return ValidationClassUnsupportedVersion, true
	case codeInvalidRequest:
		return ValidationClassInvalidRequest, true
	case codeInvalidParams:
		return ValidationClassInvalidParams, true
	case codeParseError:
		return ValidationClassParseError, true
	case codeMethodNotFound:
		return ValidationClassMethodNotFound, true
	default:
		return "", false
	}
}

func resolvedProtocolVersion(req rpcRequest, protocolHeader string) string {
	if protocolHeader != "" {
		return protocolHeader
	}
	meta := requestMetadataProtocolVersion(req.Params)
	if meta.valid {
		return meta.value
	}
	if req.Method == "initialize" {
		var params initializeParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return latestLegacyProtocolVersion
		}
		if params.ProtocolVersion != "" {
			return params.ProtocolVersion
		}
		return latestLegacyProtocolVersion
	}
	return ""
}
