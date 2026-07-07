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

package otlp

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	otellog "go.opentelemetry.io/otel/log"
)

func strptr(s string) *string { return &s }

func attrsOf(rec otellog.Record) map[string]otellog.Value {
	m := make(map[string]otellog.Value, rec.AttributesLen())
	rec.WalkAttributes(func(kv otellog.KeyValue) bool {
		m[kv.Key] = kv.Value
		return true
	})
	return m
}

func fullEvent() *events.Event {
	return &events.Event{
		SchemaVersion: events.SchemaVersion,
		TraceID:       "trace-123",
		GatewayID:     "gw-1",
		TeamID:        "team-1",
		OccurredOn:    1_700_000_000_000,
		Consumer:      events.Consumer{ID: "c-1", Name: "alice"},
		SessionID:     "sess-1",
		Status:        events.Status{Code: 200},
		Request: events.Request{
			Method:         "POST",
			Path:           "/v1/chat/completions",
			Provider:       "openai",
			Model:          "gpt-4o",
			RequestedModel: "gpt-4o-mini",
			ModelLabel:     "default",
			Stream:         false,
			Body:           "request-body",
		},
		Response: events.Response{
			StatusCode:   200,
			FinishReason: "stop",
			Body:         strptr("hello world"),
		},
		Usage: &events.Usage{
			PromptTokens:          10,
			CompletionTokens:      5,
			TotalTokens:           15,
			CachedInputTokens:     2,
			ReasoningOutputTokens: 1,
		},
		Cost:    &events.Cost{PromptUsd: events.DecimalFloat(0.002), CompletionUsd: events.DecimalFloat(0.008), TotalUsd: events.DecimalFloat(0.01), Currency: "USD"},
		Latency: events.Latency{TotalMs: 120, ProviderMs: 100, PoliciesMs: 10, RoutingMs: 5, GatewayMs: 5},
		Attempts: []events.Attempt{
			{Provider: "openai", Attempt: 1, StatusCode: 200},
		},
		PolicyChain: []events.PolicyEntry{
			{Name: "rate-limit", Stage: "pre", Decision: "allow", Extras: map[string]string{"detail": "secret"}},
		},
	}
}

func TestEventToRecord_StandardAndProprietaryCoexist(t *testing.T) {
	t.Parallel()
	rec := eventToRecord(fullEvent(), metrics.Metadata, 4096)

	assert.Equal(t, "trustgate.3.metadata", rec.EventName())
	assert.Equal(t, otellog.SeverityInfo, rec.Severity())
	assert.Equal(t, "", rec.Body().AsString())

	attrs := attrsOf(rec)

	assert.Equal(t, "openai", attrs["gen_ai.provider.name"].AsString())
	assert.Equal(t, "gpt-4o", attrs["gen_ai.request.model"].AsString())
	assert.Equal(t, int64(10), attrs["gen_ai.usage.input_tokens"].AsInt64())
	assert.Equal(t, int64(5), attrs["gen_ai.usage.output_tokens"].AsInt64())
	assert.Equal(t, "POST", attrs["http.request.method"].AsString())
	assert.Equal(t, int64(200), attrs["http.response.status_code"].AsInt64())
	assert.Equal(t, "/v1/chat/completions", attrs["url.path"].AsString())

	finish := attrs["gen_ai.response.finish_reasons"].AsSlice()
	assert.Len(t, finish, 1)
	assert.Equal(t, "stop", finish[0].AsString())

	assert.Equal(t, int64(events.SchemaVersion), attrs["trustgate.schema_version"].AsInt64())
	assert.Equal(t, "trace-123", attrs["trustgate.trace_id"].AsString())
	assert.Equal(t, "gw-1", attrs["trustgate.gateway_id"].AsString())
	assert.Equal(t, "team-1", attrs["trustgate.team_id"].AsString())
	assert.Equal(t, "c-1", attrs["trustgate.consumer.id"].AsString())
	assert.Equal(t, "alice", attrs["trustgate.consumer.name"].AsString())
	assert.InDelta(t, 0.01, attrs["trustgate.cost.total_usd"].AsFloat64(), 1e-9)
	assert.Equal(t, "USD", attrs["trustgate.cost.currency"].AsString())
	assert.Equal(t, int64(15), attrs["trustgate.usage.total_tokens"].AsInt64())
	assert.Equal(t, int64(120), attrs["trustgate.latency.total_ms"].AsInt64())

	policyChainJSON := attrs["trustgate.policy_chain"].AsString()
	assert.Contains(t, policyChainJSON, `"plugin":"rate-limit"`)
	assert.NotContains(t, policyChainJSON, "secret")

	pluginChainJSON := attrs["trustgate.plugin_chain"].AsString()
	assert.Contains(t, pluginChainJSON, "rate-limit")
	assert.NotContains(t, pluginChainJSON, `"extras"`)

	assert.Equal(t, int64(1), attrs["trustgate.attempts.count"].AsInt64())
	assert.Contains(t, attrs["trustgate.attempts"].AsString(), "openai")
	_, hasRequestBody := attrs["trustgate.request.body"]
	_, hasResponseBody := attrs["trustgate.response.body"]
	assert.False(t, hasRequestBody)
	assert.False(t, hasResponseBody)
}

func TestEventToRecord_RawIncludesBodies(t *testing.T) {
	t.Parallel()
	rec := eventToRecord(fullEvent(), metrics.Raw, 4096)
	attrs := attrsOf(rec)

	assert.Equal(t, "trustgate.3.raw", rec.EventName())
	assert.Equal(t, "", rec.Body().AsString())
	assert.Equal(t, "request-body", attrs["trustgate.request.body"].AsString())
	assert.Equal(t, "hello world", attrs["trustgate.response.body"].AsString())
}

func TestEventToRecord_MetadataViewHasNoBodies(t *testing.T) {
	t.Parallel()
	meta := events.MetadataView(fullEvent())
	rec := eventToRecord(meta, metrics.Metadata, 4096)
	attrs := attrsOf(rec)

	assert.Equal(t, "trustgate.3.metadata", rec.EventName())
	_, hasRequestBody := attrs["trustgate.request.body"]
	_, hasResponseBody := attrs["trustgate.response.body"]
	assert.False(t, hasRequestBody)
	assert.False(t, hasResponseBody)
}

func TestEventName_ResourceVersionVerb(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "trustgate.3.metadata", eventName(3, metrics.Metadata))
	assert.Equal(t, "trustgate.3.raw", eventName(3, metrics.Raw))
	assert.Equal(t, "trustgate.3.metadata", eventName(0, metrics.Metadata))
}

func TestEventToRecord_Severity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code int
		want otellog.Severity
	}{
		{"informational", 200, otellog.SeverityInfo},
		{"missing status", 0, otellog.SeverityInfo},
		{"client error", 429, otellog.SeverityWarn},
		{"server error", 500, otellog.SeverityError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			evt := fullEvent()
			evt.Status.Code = tc.code
			rec := eventToRecord(evt, metrics.Metadata, 4096)
			assert.Equal(t, tc.want, rec.Severity())
		})
	}
}

func TestEventToRecord_StatusFields(t *testing.T) {
	t.Parallel()
	evt := fullEvent()
	evt.Status = events.Status{Code: 504, IsTimeout: true, Outcome: "timeout", Reason: "upstream deadline"}
	rec := eventToRecord(evt, metrics.Metadata, 4096)
	attrs := attrsOf(rec)

	assert.Equal(t, "timeout", attrs["trustgate.status.outcome"].AsString())
	assert.Equal(t, "upstream deadline", attrs["trustgate.status.reason"].AsString())
	assert.True(t, attrs["trustgate.status.is_timeout"].AsBool())
}

func TestEventToRecord_StatusTimeoutOmittedWhenFalse(t *testing.T) {
	t.Parallel()
	rec := eventToRecord(fullEvent(), metrics.Metadata, 4096)
	attrs := attrsOf(rec)
	_, ok := attrs["trustgate.status.is_timeout"]
	assert.False(t, ok)
}

func TestEventToRecord_NoUsage(t *testing.T) {
	t.Parallel()
	evt := fullEvent()
	evt.Usage = nil
	evt.Cost = nil
	rec := eventToRecord(evt, metrics.Metadata, 4096)
	attrs := attrsOf(rec)

	_, hasInput := attrs["gen_ai.usage.input_tokens"]
	assert.False(t, hasInput)
	_, hasTotal := attrs["trustgate.usage.total_tokens"]
	assert.False(t, hasTotal)
	_, hasCost := attrs["trustgate.cost.total_usd"]
	assert.False(t, hasCost)
}

func TestEventToRecord_Streaming(t *testing.T) {
	t.Parallel()
	evt := fullEvent()
	evt.Request.Stream = true
	rec := eventToRecord(evt, metrics.Metadata, 4096)
	attrs := attrsOf(rec)
	assert.True(t, attrs["gen_ai.request.stream"].AsBool())
}

func TestEventToRecord_BodyTruncation(t *testing.T) {
	t.Parallel()
	evt := fullEvent()
	evt.Response.Body = strptr(strings.Repeat("x", 100))
	rec := eventToRecord(evt, metrics.Raw, 10)
	attrs := attrsOf(rec)
	assert.Equal(t, 10, len(attrs["trustgate.response.body"].AsString()))
}

func TestEventToRecord_EmptyTrace(t *testing.T) {
	t.Parallel()
	evt := fullEvent()
	evt.TraceID = ""
	rec := eventToRecord(evt, metrics.Metadata, 4096)
	attrs := attrsOf(rec)
	_, ok := attrs["trustgate.trace_id"]
	assert.False(t, ok)
	assert.Equal(t, "trustgate.3.metadata", rec.EventName())
}

func TestEventToRecord_Nil(t *testing.T) {
	t.Parallel()
	rec := eventToRecord(nil, metrics.Metadata, 4096)
	assert.Equal(t, "", rec.EventName())
}
