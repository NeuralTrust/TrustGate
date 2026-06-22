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

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	otellog "go.opentelemetry.io/otel/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

const eventName = "gateway.request"

// genAIRequestStreamKey is not part of stable semconv; it is kept local so a
// semconv bump does not silently move it.
const genAIRequestStreamKey = "gen_ai.request.stream"

const (
	attrSchemaVersion        = "trustgate.schema_version"
	attrKind                 = "trustgate.kind"
	attrMCPMethod            = "trustgate.mcp.method"
	attrMCPOperation         = "trustgate.mcp.operation"
	attrMCPServerName        = "trustgate.mcp.server_name"
	attrMCPRegistryID        = "trustgate.mcp.registry_id"
	attrMCPHost              = "trustgate.mcp.host"
	attrMCPCatalogCode       = "trustgate.mcp.catalog_code"
	attrMCPTransport         = "trustgate.mcp.transport"
	attrMCPTool              = "trustgate.mcp.tool"
	attrMCPUpstreamTool      = "trustgate.mcp.upstream_tool"
	attrMCPPrompt            = "trustgate.mcp.prompt"
	attrMCPResourceURI       = "trustgate.mcp.resource_uri"
	attrMCPTargets           = "trustgate.mcp.targets"
	attrMCPUpstreamStatus    = "trustgate.mcp.upstream_status"
	attrMCPUpstreamLatencyMs = "trustgate.mcp.upstream_latency_ms"
	attrMCPRPCErrorCode      = "trustgate.mcp.rpc_error_code"
	attrStatusOutcome        = "trustgate.status.outcome"
	attrStatusReason         = "trustgate.status.reason"
	attrStatusIsTimeout      = "trustgate.status.is_timeout"
	attrTraceID              = "trustgate.trace_id"
	attrGatewayID            = "trustgate.gateway_id"
	attrTeamID               = "trustgate.team_id"
	attrConsumerID           = "trustgate.consumer.id"
	attrConsumerName         = "trustgate.consumer.name"
	attrSessionID            = "trustgate.session_id"
	attrTurnID               = "trustgate.turn_id"
	attrIP                   = "trustgate.ip"
	attrRequestedModel       = "trustgate.requested_model"
	attrModelLabel           = "trustgate.model_label"
	attrUsageTotalTokens     = "trustgate.usage.total_tokens"
	attrUsageCachedInput     = "trustgate.usage.cached_input_tokens"
	attrUsageReasoningOutput = "trustgate.usage.reasoning_output_tokens"
	attrCostTotalUsd         = "trustgate.cost.total_usd"
	attrCostPromptUsd        = "trustgate.cost.prompt_usd"
	attrCostCompletionUsd    = "trustgate.cost.completion_usd"
	attrCostCurrency         = "trustgate.cost.currency"
	attrLatencyTotalMs       = "trustgate.latency.total_ms"
	attrLatencyProviderMs    = "trustgate.latency.provider_ms"
	attrLatencyPoliciesMs    = "trustgate.latency.policies_ms"
	attrLatencyRoutingMs     = "trustgate.latency.routing_ms"
	attrLatencyGatewayMs     = "trustgate.latency.gateway_ms"
	attrIsFlagged            = "trustgate.is_flagged"
	attrSecurity             = "trustgate.security"
	attrRequestBody          = "trustgate.request.body"
	attrPolicyChain          = "trustgate.policy_chain"
	attrAttempts             = "trustgate.attempts"
	attrAttemptsCount        = "trustgate.attempts.count"
)

// eventToRecord is the single, semconv-pinned (semconv/v1.41.0) mapping from a
// sanitized business Event to an OTLP log record. Standard fields use GenAI/HTTP
// semantic conventions; gateway-specific fields use the trustgate.* namespace.
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
	appendStr(attrKind, evt.Kind)
	if evt.MCP != nil {
		appendStr(attrMCPMethod, evt.MCP.Method)
		appendStr(attrMCPOperation, evt.MCP.Operation)
		appendStr(attrMCPServerName, evt.MCP.ServerName)
		appendStr(attrMCPRegistryID, evt.MCP.RegistryID)
		appendStr(attrMCPHost, evt.MCP.Host)
		appendStr(attrMCPCatalogCode, evt.MCP.CatalogCode)
		appendStr(attrMCPTransport, evt.MCP.Transport)
		appendStr(attrMCPTool, evt.MCP.Tool)
		appendStr(attrMCPUpstreamTool, evt.MCP.UpstreamTool)
		appendStr(attrMCPPrompt, evt.MCP.Prompt)
		appendStr(attrMCPResourceURI, evt.MCP.ResourceURI)
		appendStr(attrMCPUpstreamStatus, evt.MCP.UpstreamStatus)
		if evt.MCP.Targets > 0 {
			attrs = append(attrs, otellog.Int(attrMCPTargets, evt.MCP.Targets))
		}
		if evt.MCP.UpstreamLatencyMs > 0 {
			attrs = append(attrs, otellog.Int64(attrMCPUpstreamLatencyMs, evt.MCP.UpstreamLatencyMs))
		}
		if evt.MCP.RPCErrorCode != 0 {
			attrs = append(attrs, otellog.Int(attrMCPRPCErrorCode, evt.MCP.RPCErrorCode))
		}
	}
	appendStr(attrTraceID, evt.TraceID)
	appendStr(attrGatewayID, evt.GatewayID)
	appendStr(attrTeamID, evt.TeamID)
	appendStr(attrConsumerID, evt.Consumer.ID)
	appendStr(attrConsumerName, evt.Consumer.Name)
	appendStr(attrSessionID, evt.SessionID)
	appendStr(attrTurnID, evt.TurnID)
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
