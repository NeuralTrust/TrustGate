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
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

// eventName is the OTLP LogRecord routing key downstream consumers key on. It
// follows resource.version.verb: the resource is always trustgate, the version
// tracks the event schema, and the verb is the data class (metadata or raw), so
// a single trace produces trustgate.1.metadata and trustgate.1.raw.
func eventName(schemaVersion int, class metrics.DataClass) string {
	if schemaVersion <= 0 {
		schemaVersion = metrics.SchemaVersion
	}
	return fmt.Sprintf("trustgate.%d.%s", schemaVersion, class)
}

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
	attrMCPAccountRef        = "trustgate.mcp.account_ref"
	attrStatusOutcome        = "trustgate.status.outcome"
	attrStatusReason         = "trustgate.status.reason"
	attrStatusIsTimeout      = "trustgate.status.is_timeout"
	attrTraceID              = "trustgate.trace_id"
	attrGatewayID            = "trustgate.gateway_id"
	attrTenantID             = "trustgate.tenant_id"
	attrConsumerID           = "trustgate.consumer.id"
	attrConsumerName         = "trustgate.consumer.name"
	attrPrincipalSubject     = "trustgate.principal.subject"
	attrPrincipalMethod      = "trustgate.principal.method"
	attrPrincipalEmail       = "trustgate.principal.email"
	attrSessionID            = "trustgate.session_id"
	attrTurnID               = "trustgate.turn_id"
	attrIP                   = "trustgate.ip"
	attrRequestedModel       = "trustgate.requested_model"
	attrModelLabel           = "trustgate.model_label"
	attrUsageTotalTokens     = "trustgate.usage.total_tokens"
	attrUsageCachedInput     = "trustgate.usage.cached_input_tokens"
	attrUsageCacheWrite      = "trustgate.usage.cache_write_input_tokens"
	attrUsageCacheWrite1h    = "trustgate.usage.cache_write_1h_input_tokens"
	attrUsageToolUseInput    = "trustgate.usage.tool_use_input_tokens"
	attrUsageReasoningOutput = "trustgate.usage.reasoning_output_tokens"
	attrCostTotalUsd         = "trustgate.cost.total_usd"
	attrCostPromptUsd        = "trustgate.cost.prompt_usd"
	attrCostCompletionUsd    = "trustgate.cost.completion_usd"
	attrCostCurrency         = "trustgate.cost.currency"
	attrCostSavingsUsd       = "trustgate.cost.savings_usd"
	attrLatencyTotalMs       = "trustgate.latency.total_ms"
	attrLatencyProviderMs    = "trustgate.latency.provider_ms"
	attrLatencyPoliciesMs    = "trustgate.latency.policies_ms"
	attrLatencyGatewayMs     = "trustgate.latency.gateway_ms"
	attrIsFlagged            = "trustgate.is_flagged"
	attrSecurity             = "trustgate.security"
	attrPolicyChain          = "trustgate.policy_chain"
	attrAttempts             = "trustgate.attempts"
	attrAttemptsCount        = "trustgate.attempts.count"
	attrRetentionExpiresAt   = "trustgate.retention.expires_at"
	attrRetentionPlan        = "trustgate.retention.plan"
	attrRequestBody          = "trustgate.request.body"
	attrResponseBody         = "trustgate.response.body"
)

// eventToRecord is the single, semconv-pinned (semconv/v1.41.0) mapping from a
// sanitized business Event to an OTLP log record. Standard fields use GenAI/HTTP
// semantic conventions; gateway-specific fields use the trustgate.* namespace.
func eventToRecord(evt *events.Event) otellog.Record {
	var rec otellog.Record
	if evt == nil {
		return rec
	}

	rec.SetEventName(eventName(evt.SchemaVersion, metrics.Metadata))
	if evt.OccurredOn > 0 {
		rec.SetTimestamp(time.UnixMilli(evt.OccurredOn))
	}
	rec.SetObservedTimestamp(time.Now())
	rec.SetSeverity(severityForStatus(evt.Status.Code))

	attrs := make([]attribute.KeyValue, 0, 32)
	appendStr := func(key, value string) {
		if value != "" {
			attrs = append(attrs, attribute.String(key, value))
		}
	}

	appendStr(string(semconv.HTTPRequestMethodKey), evt.Request.Method)
	attrs = append(attrs, attribute.Int(string(semconv.HTTPResponseStatusCodeKey), evt.Response.StatusCode))
	appendStr(string(semconv.URLPathKey), evt.Request.Path)
	appendStr(string(semconv.GenAIProviderNameKey), evt.Request.Provider)
	appendStr(string(semconv.GenAIRequestModelKey), evt.Request.Model)
	if evt.Response.FinishReason != "" {
		attrs = append(attrs, attribute.StringSlice(
			string(semconv.GenAIResponseFinishReasonsKey),
			[]string{evt.Response.FinishReason},
		))
	}
	attrs = append(attrs, attribute.Bool(genAIRequestStreamKey, evt.Request.Stream || evt.Response.Streaming))
	if evt.Usage != nil {
		attrs = append(attrs,
			attribute.Int(string(semconv.GenAIUsageInputTokensKey), evt.Usage.PromptTokens),
			attribute.Int(string(semconv.GenAIUsageOutputTokensKey), evt.Usage.CompletionTokens),
			attribute.Int(attrUsageTotalTokens, evt.Usage.TotalTokens),
		)
		if evt.Usage.CachedInputTokens > 0 {
			attrs = append(attrs, attribute.Int(attrUsageCachedInput, evt.Usage.CachedInputTokens))
		}
		if evt.Usage.CacheWriteInputTokens > 0 {
			attrs = append(attrs, attribute.Int(attrUsageCacheWrite, evt.Usage.CacheWriteInputTokens))
		}
		if evt.Usage.CacheWrite1hInputTokens > 0 {
			attrs = append(attrs, attribute.Int(attrUsageCacheWrite1h, evt.Usage.CacheWrite1hInputTokens))
		}
		if evt.Usage.ToolUseInputTokens > 0 {
			attrs = append(attrs, attribute.Int(attrUsageToolUseInput, evt.Usage.ToolUseInputTokens))
		}
		if evt.Usage.ReasoningOutputTokens > 0 {
			attrs = append(attrs, attribute.Int(attrUsageReasoningOutput, evt.Usage.ReasoningOutputTokens))
		}
	}

	attrs = append(attrs, attribute.Int(attrSchemaVersion, evt.SchemaVersion))
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
		if evt.MCP.UpstreamStatus != 0 {
			attrs = append(attrs, attribute.Int(attrMCPUpstreamStatus, evt.MCP.UpstreamStatus))
		}
		if evt.MCP.Targets > 0 {
			attrs = append(attrs, attribute.Int(attrMCPTargets, evt.MCP.Targets))
		}
		if evt.MCP.UpstreamLatencyMs > 0 {
			attrs = append(attrs, attribute.Int64(attrMCPUpstreamLatencyMs, evt.MCP.UpstreamLatencyMs))
		}
		if evt.MCP.RPCErrorCode != 0 {
			attrs = append(attrs, attribute.Int(attrMCPRPCErrorCode, evt.MCP.RPCErrorCode))
		}
		appendStr(attrMCPAccountRef, evt.MCP.AccountRef)
	}
	appendStr(attrTraceID, evt.TraceID)
	appendStr(attrGatewayID, evt.GatewayID)
	appendStr(attrTenantID, evt.TenantID)
	appendStr(attrConsumerID, evt.Consumer.ID)
	appendStr(attrConsumerName, evt.Consumer.Name)
	appendStr(attrPrincipalSubject, evt.PrincipalSubject)
	appendStr(attrPrincipalMethod, evt.PrincipalMethod)
	appendStr(attrPrincipalEmail, evt.PrincipalEmail)
	appendStr(attrSessionID, evt.SessionID)
	appendStr(attrTurnID, evt.TurnID)
	appendStr(attrIP, evt.IP)
	appendStr(attrRequestedModel, evt.Request.RequestedModel)
	appendStr(attrModelLabel, evt.Request.ModelLabel)
	appendStr(attrStatusOutcome, evt.Status.Outcome)
	appendStr(attrStatusReason, evt.Status.Reason)
	if evt.Status.IsTimeout {
		attrs = append(attrs, attribute.Bool(attrStatusIsTimeout, true))
	}
	if evt.Cost != nil {
		attrs = append(attrs,
			attribute.Float64(attrCostTotalUsd, float64(evt.Cost.TotalUsd)),
			attribute.Float64(attrCostPromptUsd, float64(evt.Cost.PromptUsd)),
			attribute.Float64(attrCostCompletionUsd, float64(evt.Cost.CompletionUsd)),
		)
		appendStr(attrCostCurrency, evt.Cost.Currency)
		if evt.Cost.SavingsUsd != nil {
			attrs = append(attrs, attribute.Float64(attrCostSavingsUsd, float64(*evt.Cost.SavingsUsd)))
		}
	}
	attrs = append(attrs,
		attribute.Int64(attrLatencyTotalMs, evt.Latency.TotalMs),
		attribute.Int64(attrLatencyProviderMs, evt.Latency.ProviderMs),
		attribute.Int64(attrLatencyPoliciesMs, evt.Latency.PoliciesMs),
		attribute.Int64(attrLatencyGatewayMs, evt.Latency.GatewayMs),
		attribute.Bool(attrIsFlagged, evt.IsFlagged),
	)
	if len(evt.Security) > 0 {
		attrs = append(attrs, attribute.StringSlice(attrSecurity, evt.Security))
	}
	if len(evt.PolicyChain) > 0 {
		if encoded := jsonString(evt.PolicyChain); encoded != "" {
			attrs = append(attrs, attribute.String(attrPolicyChain, encoded))
		}
	}
	if len(evt.Attempts) > 0 {
		if encoded := jsonString(evt.Attempts); encoded != "" {
			attrs = append(attrs, attribute.String(attrAttempts, encoded))
		}
		attrs = append(attrs, attribute.Int(attrAttemptsCount, len(evt.Attempts)))
	}

	attrs = appendRetention(attrs, evt)

	rec.AddAttributes(attrs...)
	return rec
}

func rawEventToRecord(evt *events.Event) otellog.Record {
	var rec otellog.Record
	if evt == nil {
		return rec
	}

	rec.SetEventName(eventName(evt.SchemaVersion, metrics.Raw))
	if evt.OccurredOn > 0 {
		rec.SetTimestamp(time.UnixMilli(evt.OccurredOn))
	}
	rec.SetObservedTimestamp(time.Now())

	attrs := make([]attribute.KeyValue, 0, 8)
	appendStr := func(key, value string) {
		if value != "" {
			attrs = append(attrs, attribute.String(key, value))
		}
	}

	attrs = append(attrs, attribute.Int(attrSchemaVersion, evt.SchemaVersion))
	appendStr(attrTraceID, evt.TraceID)
	appendStr(attrGatewayID, evt.GatewayID)
	appendStr(attrTenantID, evt.TenantID)
	appendStr(attrRequestBody, evt.Request.Body)
	if evt.Response.Body != nil {
		appendStr(attrResponseBody, *evt.Response.Body)
	}
	attrs = appendRetention(attrs, evt)

	rec.AddAttributes(attrs...)
	return rec
}

// appendRetention adds the plan-derived expiry the storage layer keys its TTL on.
// Nothing is added when the gateway carries no stamp, so the sink falls back to its
// own policy rather than inheriting an expiry nobody set.
func appendRetention(attrs []attribute.KeyValue, evt *events.Event) []attribute.KeyValue {
	if evt.Retention == nil || evt.Retention.ExpiresAt <= 0 {
		return attrs
	}
	attrs = append(attrs, attribute.Int64(attrRetentionExpiresAt, evt.Retention.ExpiresAt))
	if evt.Retention.Plan != "" {
		attrs = append(attrs, attribute.String(attrRetentionPlan, evt.Retention.Plan))
	}
	return attrs
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

func jsonString(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}
