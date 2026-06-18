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

package metrics

import (
	"context"
	"net/http"
	"time"

	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
	routingdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
)

const costCurrencyUSD = "USD"

type Builder struct {
	adapters *adapter.Registry
	pricing  appcatalog.PricingResolver
}

func NewBuilder(adapters *adapter.Registry, pricing appcatalog.PricingResolver) *Builder {
	return &Builder{adapters: adapters, pricing: pricing}
}

func (b *Builder) Build(
	ctx context.Context,
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime, endTime time.Time,
) *events.Event {
	meta := trace.Metadata{}
	traceID := ""
	if requestTrace != nil {
		meta = requestTrace.Metadata()
		traceID = requestTrace.TraceID()
	}

	evt := &events.Event{
		SchemaVersion: events.SchemaVersion,
		Kind:          events.KindLLM,
		TraceID:       traceID,
		GatewayID:     meta.GatewayID,
		TeamID:        meta.TeamID,
		Timestamp:     startTime.UTC().Format(time.RFC3339),
		OccurredOn:    startTime.UnixMilli(),
		EndTimestamp:  endTime.UnixMilli(),
		Consumer:      events.Consumer{ID: meta.ConsumerID, Name: meta.ConsumerName},
		SessionID:     meta.SessionID,
		IP:            meta.IP,
	}

	if meta.Kind == events.KindMCP {
		return b.buildMCP(evt, req, resp, requestTrace, startTime, endTime)
	}

	served, attempts := b.foldLLMSpans(requestTrace)
	if served != nil {
		evt.TurnID = served.TurnID
	}
	chain, pluginsMs, flagged, security := b.foldPluginSpans(requestTrace)
	evt.Attempts = attempts
	evt.PolicyChain = chain
	evt.IsFlagged = flagged
	evt.Security = security

	totalMs := endTime.Sub(startTime).Milliseconds()
	providerMs := sumAttemptLatency(attempts)
	routingMs := maxInt64(0, totalMs-providerMs-pluginsMs)
	evt.Latency = events.Latency{
		TotalMs:    totalMs,
		ProviderMs: providerMs,
		PoliciesMs: pluginsMs,
		RoutingMs:  routingMs,
		GatewayMs:  pluginsMs + routingMs,
	}

	b.fillRequest(evt, req, served)
	b.fillResponse(evt, resp, served, totalMs)
	b.fillStatus(evt, resp, served, requestTrace)
	b.fillUsageAndCost(ctx, evt, served)

	return evt
}

func (b *Builder) foldLLMSpans(requestTrace *trace.RequestTrace) (*trace.LLMAttrs, []events.Attempt) {
	if requestTrace == nil {
		return nil, nil
	}
	var served *trace.LLMAttrs
	var attempts []events.Attempt
	for _, span := range requestTrace.Spans() {
		if span.Type != trace.SpanLLM {
			continue
		}
		attrs, ok := span.LLMAttrsCopy()
		if !ok {
			continue
		}
		copied := attrs
		served = &copied
		attempts = append(attempts, events.Attempt{
			RegistryID: attrs.RegistryID,
			Provider:   attrs.Provider,
			Attempt:    attrs.Attempt,
			Fallback:   attrs.Fallback,
			Pinned:     attrs.Pinned,
			Route:      attrs.Route,
			Outcome:    attrs.Outcome,
			StatusCode: span.StatusCode(),
			LatencyMs:  span.Latency().Milliseconds(),
		})
	}
	return served, attempts
}

func (b *Builder) foldPluginSpans(requestTrace *trace.RequestTrace) ([]events.PolicyEntry, int64, bool, []string) {
	if requestTrace == nil {
		return nil, 0, false, nil
	}
	var chain []events.PolicyEntry
	var pluginsMs int64
	anyFlagged := false
	seenLabels := make(map[string]struct{})
	var security []string
	for _, span := range requestTrace.Spans() {
		if span.Type != trace.SpanPlugin {
			continue
		}
		attrs := span.PluginAttrsCopy()
		statusCode := span.StatusCode()
		hasError := span.Error() != ""
		flagged := hasError || attrs.Decision == "block" || (statusCode >= http.StatusBadRequest)
		latencyMs := span.Latency().Milliseconds()
		pluginsMs += latencyMs
		if flagged {
			anyFlagged = true
			if attrs.ScoreLabel != "" {
				if _, dup := seenLabels[attrs.ScoreLabel]; !dup {
					seenLabels[attrs.ScoreLabel] = struct{}{}
					security = append(security, attrs.ScoreLabel)
				}
			}
		}
		chain = append(chain, events.PolicyEntry{
			Name:       span.Name,
			Stage:      attrs.Stage,
			Decision:   attrs.Decision,
			LatencyMs:  latencyMs,
			StatusCode: statusCode,
			Error:      hasError,
			Flagged:    flagged,
			Score:      attrs.Score,
			ScoreLabel: attrs.ScoreLabel,
			Extras:     attrs.Extras,
		})
	}
	return chain, pluginsMs, anyFlagged, security
}

func (b *Builder) buildMCP(
	evt *events.Event,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	requestTrace *trace.RequestTrace,
	startTime, endTime time.Time,
) *events.Event {
	evt.Kind = events.KindMCP

	mcp, upstreamMs := b.foldMCPSpans(requestTrace)
	if mcp != nil {
		mcp.UpstreamLatencyMs = upstreamMs
	}
	evt.MCP = mcp

	totalMs := endTime.Sub(startTime).Milliseconds()
	gatewayMs := maxInt64(0, totalMs-upstreamMs)
	evt.Latency = events.Latency{
		TotalMs:    totalMs,
		ProviderMs: upstreamMs,
		GatewayMs:  gatewayMs,
	}

	b.fillRequest(evt, req, nil)
	b.fillResponse(evt, resp, nil, totalMs)
	b.fillStatus(evt, resp, nil, requestTrace)
	return evt
}

func (b *Builder) foldMCPSpans(requestTrace *trace.RequestTrace) (*events.MCP, int64) {
	if requestTrace == nil {
		return nil, 0
	}
	var mcp *events.MCP
	var upstreamMs int64
	for _, span := range requestTrace.Spans() {
		if span.Type != trace.SpanMCP {
			continue
		}
		attrs, ok := span.MCPAttrsCopy()
		if !ok {
			continue
		}
		upstreamMs += span.Latency().Milliseconds()
		mcp = &events.MCP{
			Method:         attrs.Method,
			Operation:      attrs.Operation,
			ServerName:     attrs.ServerName,
			RegistryID:     attrs.RegistryID,
			Host:           attrs.Host,
			CatalogCode:    attrs.CatalogCode,
			Transport:      attrs.Transport,
			Tool:           attrs.Tool,
			UpstreamTool:   attrs.UpstreamTool,
			Prompt:         attrs.Prompt,
			ResourceURI:    attrs.ResourceURI,
			Targets:        attrs.Targets,
			UpstreamStatus: attrs.UpstreamStatus,
			RPCErrorCode:   attrs.RPCErrorCode,
		}
	}
	return mcp, upstreamMs
}

func (b *Builder) fillRequest(evt *events.Event, req *infracontext.RequestContext, served *trace.LLMAttrs) {
	evt.Request = events.Request{
		Method:         req.Method,
		Path:           req.Path,
		RequestedModel: req.RequestedModel,
		Body:           events.SanitizeBody(req.Body, req.Headers),
		Headers:        events.RedactHeaders(req.Headers),
	}
	if served != nil {
		evt.Request.Provider = served.Provider
		evt.Request.RegistryID = served.RegistryID
		evt.Request.Model = served.Model
	}
	canonical := b.decodeRequest(req)
	if canonical == nil {
		return
	}
	if evt.Request.Model == "" {
		evt.Request.Model = canonical.Model
	}
	evt.Request.Temperature = canonical.Temperature
	evt.Request.MaxTokens = canonical.MaxTokens
	evt.Request.Stream = canonical.Stream
}

func (b *Builder) decodeRequest(req *infracontext.RequestContext) *adapter.CanonicalRequest {
	if b.adapters == nil || len(req.Body) == 0 {
		return nil
	}
	format := adapter.Format(req.SourceFormat)
	if format == "" {
		format = adapter.DetectFormat(req.Body)
	}
	canonical, err := b.adapters.DecodeRequestFor(req.Body, format)
	if err != nil {
		return nil
	}
	return canonical
}

func (b *Builder) fillResponse(evt *events.Event, resp *infracontext.ResponseContext, served *trace.LLMAttrs, totalMs int64) {
	evt.Response = events.Response{
		StatusCode: resp.StatusCode,
		LatencyMs:  totalMs,
		Streaming:  resp.Streaming,
		Headers:    events.RedactHeaders(resp.Headers),
	}
	if served != nil {
		evt.Response.FinishReason = served.FinishReason
	}
	if len(resp.Body) > 0 {
		body := events.SanitizeBodyFull(resp.Body, resp.Headers)
		evt.Response.Body = &body
	}
}

func (b *Builder) fillStatus(
	evt *events.Event,
	resp *infracontext.ResponseContext,
	served *trace.LLMAttrs,
	requestTrace *trace.RequestTrace,
) {
	outcome := ""
	if served != nil {
		outcome = served.Outcome
	}
	reason := ""
	if requestTrace != nil {
		reason = requestTrace.StatusReason()
	}
	evt.Status = events.Status{
		Code:      resp.StatusCode,
		IsTimeout: resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout,
		Outcome:   outcome,
		Reason:    reason,
	}
}

func (b *Builder) fillUsageAndCost(ctx context.Context, evt *events.Event, served *trace.LLMAttrs) {
	if served == nil || served.Usage == nil {
		return
	}
	u := served.Usage
	evt.Usage = &events.Usage{
		PromptTokens:          u.InputTokens,
		CompletionTokens:      u.OutputTokens,
		TotalTokens:           u.TotalTokens,
		CachedInputTokens:     u.CachedInputTokens,
		ReasoningOutputTokens: u.ReasoningOutputTokens,
	}
	evt.Request.PromptTokens = u.InputTokens
	evt.Response.CompletionTokens = u.OutputTokens

	if b.pricing == nil || served.Provider == "" {
		return
	}
	var price appcatalog.Pricing
	for _, slug := range pricingSlugs(evt, served) {
		price = b.pricing.Resolve(ctx, served.Provider, slug)
		if price.Found {
			break
		}
	}
	if !price.Found {
		return
	}
	if price.ModelLabel != "" {
		evt.Request.ModelLabel = price.ModelLabel
	}
	promptUsd := float64(u.InputTokens) * price.InputPrice
	completionUsd := float64(u.OutputTokens) * price.OutputPrice
	evt.Cost = &events.Cost{
		PromptUsd:     events.DecimalFloat(promptUsd),
		CompletionUsd: events.DecimalFloat(completionUsd),
		TotalUsd:      events.DecimalFloat(promptUsd + completionUsd),
		Currency:      costCurrencyUSD,
	}
}

// pricingSlugs returns catalog lookup candidates, against served.Provider,
// ordered by how reliably each identifies the model that was actually billed:
//
//  1. SentModel: the model the gateway put on the outbound request after
//     routing-ref parsing, pool/LB resolution and model enforcement. It already
//     matches the models.dev catalog slug, so it is the primary source.
//  2. Model: the model echoed by the provider response (precise, may carry a
//     date suffix that is stripped to match the catalog; empty for providers
//     such as Bedrock Titan/Llama/Mistral that do not echo it).
//  3. The client-requested model (qualified @provider/model or a bare string;
//     pools contribute nothing) as a last resort.
//
// Each candidate is tried raw and with its -YYYY-MM-DD deployment suffix stripped.
func pricingSlugs(evt *events.Event, served *trace.LLMAttrs) []string {
	var slugs []string
	if served != nil {
		slugs = appendModelSlugs(slugs, served.SentModel)
		slugs = appendModelSlugs(slugs, served.Model)
	}
	slugs = appendModelSlugs(slugs, servedModel(evt, served))
	intent, _ := routingdomain.ParseModelRef(requestedModelRef(evt, served))
	slugs = appendModelSlugs(slugs, intent.Model)
	return uniqueNonEmptySlugs(slugs...)
}

func appendModelSlugs(dst []string, model string) []string {
	if model == "" {
		return dst
	}
	dst = append(dst, model)
	if base := deploymentCatalogSlug(model); base != model {
		dst = append(dst, base)
	}
	return dst
}

func requestedModelRef(evt *events.Event, served *trace.LLMAttrs) string {
	if evt != nil && evt.Request.RequestedModel != "" {
		return evt.Request.RequestedModel
	}
	if served != nil {
		return served.RequestedModel
	}
	return ""
}

func servedModel(evt *events.Event, served *trace.LLMAttrs) string {
	if evt != nil && evt.Request.Model != "" {
		return evt.Request.Model
	}
	if served != nil {
		return served.Model
	}
	return ""
}

func deploymentCatalogSlug(model string) string {
	const dateSuffixLen = 10
	if len(model) <= dateSuffixLen+1 {
		return model
	}
	suffix := model[len(model)-dateSuffixLen:]
	if suffix[4] != '-' || suffix[7] != '-' {
		return model
	}
	for _, ch := range suffix {
		if ch != '-' && (ch < '0' || ch > '9') {
			return model
		}
	}
	return model[:len(model)-dateSuffixLen-1]
}

func uniqueNonEmptySlugs(slugs ...string) []string {
	seen := make(map[string]struct{}, len(slugs))
	out := make([]string, 0, len(slugs))
	for _, slug := range slugs {
		if slug == "" {
			continue
		}
		if _, dup := seen[slug]; dup {
			continue
		}
		seen[slug] = struct{}{}
		out = append(out, slug)
	}
	return out
}

func sumAttemptLatency(attempts []events.Attempt) int64 {
	var total int64
	for _, a := range attempts {
		total += a.LatencyMs
	}
	return total
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
