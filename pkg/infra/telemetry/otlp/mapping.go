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
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	otellog "go.opentelemetry.io/otel/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

const eventName = "gateway.request"

// genAIRequestStreamKey is not part of stable semconv; it is kept local so a
// semconv bump does not silently move it.
const genAIRequestStreamKey = "gen_ai.request.stream"

const (
	attrSchemaVersion        = "agentgateway.schema_version"
	attrStatusOutcome        = "agentgateway.status.outcome"
	attrStatusReason         = "agentgateway.status.reason"
	attrStatusIsTimeout      = "agentgateway.status.is_timeout"
	attrTraceID              = "agentgateway.trace_id"
	attrGatewayID            = "agentgateway.gateway_id"
	attrTeamID               = "agentgateway.team_id"
	attrConsumerID           = "agentgateway.consumer.id"
	attrConsumerName         = "agentgateway.consumer.name"
	attrSessionID            = "agentgateway.session_id"
	attrTurnID               = "agentgateway.turn_id"
	attrFingerprintID        = "agentgateway.fingerprint_id"
	attrIP                   = "agentgateway.ip"
	attrRequestedModel       = "agentgateway.requested_model"
	attrModelLabel           = "agentgateway.model_label"
	attrUsageTotalTokens     = "agentgateway.usage.total_tokens"
	attrUsageCachedInput     = "agentgateway.usage.cached_input_tokens"
	attrUsageReasoningOutput = "agentgateway.usage.reasoning_output_tokens"
	attrCostTotalUsd         = "agentgateway.cost.total_usd"
	attrCostPromptUsd        = "agentgateway.cost.prompt_usd"
	attrCostCompletionUsd    = "agentgateway.cost.completion_usd"
	attrCostCurrency         = "agentgateway.cost.currency"
	attrLatencyTotalMs       = "agentgateway.latency.total_ms"
	attrLatencyProviderMs    = "agentgateway.latency.provider_ms"
	attrLatencyPoliciesMs    = "agentgateway.latency.policies_ms"
	attrLatencyRoutingMs     = "agentgateway.latency.routing_ms"
	attrLatencyGatewayMs     = "agentgateway.latency.gateway_ms"
	attrIsFlagged            = "agentgateway.is_flagged"
	attrSecurity             = "agentgateway.security"
	attrRequestBody          = "agentgateway.request.body"
	attrPolicyChain          = "agentgateway.policy_chain"
	attrAttempts             = "agentgateway.attempts"
	attrAttemptsCount        = "agentgateway.attempts.count"
)

// eventToRecord is the single, semconv-pinned (semconv/v1.41.0) mapping from a
// sanitized business Event to an OTLP log record. Standard fields use GenAI/HTTP
// semantic conventions; gateway-specific fields use the agentgateway.* namespace.
func eventToRecord(evt *events.Event, maxBodyBytes int) otellog.Record {
	var rec otellog.Record
	if evt == nil {
		return rec
	}

	rec.SetEventName(eventName)
	if evt.OccurredOn > 0 {
		rec.SetTimestamp(time.UnixMilli(evt.OccurredOn))
	}
	rec.SetObservedTimestamp(time.Now())
	rec.SetSeverity(severityForStatus(evt.Status.Code))

	if body := responseBody(evt, maxBodyBytes); body != "" {
		rec.SetBody(otellog.StringValue(body))
	}

	attrs := make([]otellog.KeyValue, 0, 32)
	appendStr := func(key, value string) {
		if value != "" {
			attrs = append(attrs, otellog.String(key, value))
		}
	}

	appendStr(string(semconv.HTTPRequestMethodKey), evt.Request.Method)
	attrs = append(attrs, otellog.Int(string(semconv.HTTPResponseStatusCodeKey), evt.Response.StatusCode))
	appendStr(string(semconv.URLPathKey), evt.Request.Path)
	appendStr(string(semconv.GenAIProviderNameKey), evt.Request.Provider)
	appendStr(string(semconv.GenAIRequestModelKey), evt.Request.Model)
	if evt.Response.FinishReason != "" {
		attrs = append(attrs, otellog.Slice(
			string(semconv.GenAIResponseFinishReasonsKey),
			otellog.StringValue(evt.Response.FinishReason),
		))
	}
	attrs = append(attrs, otellog.Bool(genAIRequestStreamKey, evt.Request.Stream || evt.Response.Streaming))
	if evt.Usage != nil {
		attrs = append(attrs,
			otellog.Int(string(semconv.GenAIUsageInputTokensKey), evt.Usage.PromptTokens),
			otellog.Int(string(semconv.GenAIUsageOutputTokensKey), evt.Usage.CompletionTokens),
			otellog.Int(attrUsageTotalTokens, evt.Usage.TotalTokens),
		)
		if evt.Usage.CachedInputTokens > 0 {
			attrs = append(attrs, otellog.Int(attrUsageCachedInput, evt.Usage.CachedInputTokens))
		}
		if evt.Usage.ReasoningOutputTokens > 0 {
			attrs = append(attrs, otellog.Int(attrUsageReasoningOutput, evt.Usage.ReasoningOutputTokens))
		}
	}

	attrs = append(attrs, otellog.Int(attrSchemaVersion, evt.SchemaVersion))
	appendStr(attrTraceID, evt.TraceID)
	appendStr(attrGatewayID, evt.GatewayID)
	appendStr(attrTeamID, evt.TeamID)
	appendStr(attrConsumerID, evt.Consumer.ID)
	appendStr(attrConsumerName, evt.Consumer.Name)
	appendStr(attrSessionID, evt.SessionID)
	appendStr(attrTurnID, evt.TurnID)
	appendStr(attrFingerprintID, evt.FingerprintID)
	appendStr(attrIP, evt.IP)
	appendStr(attrRequestedModel, evt.Request.RequestedModel)
	appendStr(attrModelLabel, evt.Request.ModelLabel)
	appendStr(attrStatusOutcome, evt.Status.Outcome)
	appendStr(attrStatusReason, evt.Status.Reason)
	if evt.Status.IsTimeout {
		attrs = append(attrs, otellog.Bool(attrStatusIsTimeout, true))
	}
	if evt.Cost != nil {
		attrs = append(attrs,
			otellog.Float64(attrCostTotalUsd, float64(evt.Cost.TotalUsd)),
			otellog.Float64(attrCostPromptUsd, float64(evt.Cost.PromptUsd)),
			otellog.Float64(attrCostCompletionUsd, float64(evt.Cost.CompletionUsd)),
		)
		appendStr(attrCostCurrency, evt.Cost.Currency)
	}
	attrs = append(attrs,
		otellog.Int64(attrLatencyTotalMs, evt.Latency.TotalMs),
		otellog.Int64(attrLatencyProviderMs, evt.Latency.ProviderMs),
		otellog.Int64(attrLatencyPoliciesMs, evt.Latency.PoliciesMs),
		otellog.Int64(attrLatencyRoutingMs, evt.Latency.RoutingMs),
		otellog.Int64(attrLatencyGatewayMs, evt.Latency.GatewayMs),
		otellog.Bool(attrIsFlagged, evt.IsFlagged),
	)
	if len(evt.Security) > 0 {
		attrs = append(attrs, otellog.Slice(attrSecurity, stringValues(evt.Security)...))
	}
	if requestBody := truncate(evt.Request.Body, maxBodyBytes); requestBody != "" {
		attrs = append(attrs, otellog.String(attrRequestBody, requestBody))
	}
	if len(evt.PolicyChain) > 0 {
		if encoded := jsonString(evt.PolicyChain); encoded != "" {
			attrs = append(attrs, otellog.String(attrPolicyChain, encoded))
		}
	}
	if len(evt.Attempts) > 0 {
		if encoded := jsonString(evt.Attempts); encoded != "" {
			attrs = append(attrs, otellog.String(attrAttempts, encoded))
		}
		attrs = append(attrs, otellog.Int(attrAttemptsCount, len(evt.Attempts)))
	}

	rec.AddAttributes(attrs...)
	return rec
}

func severityForStatus(code int) otellog.Severity {
	switch {
	case code >= 500:
		return otellog.SeverityError
	case code >= 400:
		return otellog.SeverityWarn
	default:
		return otellog.SeverityInfo
	}
}

func responseBody(evt *events.Event, maxBodyBytes int) string {
	if evt.Response.Body == nil {
		return ""
	}
	return truncate(*evt.Response.Body, maxBodyBytes)
}

// truncate caps s at maxBytes, trimming back to the last valid UTF-8 boundary so
// the emitted attribute is never a malformed string.
func truncate(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	truncated := s[:maxBytes]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

func stringValues(in []string) []otellog.Value {
	out := make([]otellog.Value, 0, len(in))
	for _, value := range in {
		out = append(out, otellog.StringValue(value))
	}
	return out
}

func jsonString(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}
