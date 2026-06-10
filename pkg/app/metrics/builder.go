package metrics

import (
	"context"
	"net/http"
	"time"

	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
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
		SchemaVersion:  events.SchemaVersion,
		TraceID:        traceID,
		GatewayID:      meta.GatewayID,
		Timestamp:      startTime.UTC().Format(time.RFC3339),
		StartTimestamp: startTime.UnixMilli(),
		EndTimestamp:   endTime.UnixMilli(),
		Consumer:       events.Consumer{ID: meta.ConsumerID, Name: meta.ConsumerName},
		SessionID:      meta.SessionID,
		FingerprintID:  meta.FingerprintID,
		IP:             meta.IP,
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
	b.fillStatus(evt, resp, served)
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

func (b *Builder) fillRequest(evt *events.Event, req *infracontext.RequestContext, served *trace.LLMAttrs) {
	evt.Request = events.Request{
		Method:  req.Method,
		Path:    req.Path,
		Body:    events.SanitizeBody(req.Body, req.Headers),
		Headers: events.RedactHeaders(req.Headers),
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

func (b *Builder) fillStatus(evt *events.Event, resp *infracontext.ResponseContext, served *trace.LLMAttrs) {
	outcome := ""
	if served != nil {
		outcome = served.Outcome
	}
	evt.Status = events.Status{
		Code:      resp.StatusCode,
		IsTimeout: resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout,
		Outcome:   outcome,
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

	if b.pricing == nil || served.Provider == "" || evt.Request.Model == "" {
		return
	}
	price := b.pricing.Resolve(ctx, served.Provider, evt.Request.Model)
	if !price.Found {
		return
	}
	if price.ModelLabel != "" {
		evt.Request.ModelLabel = price.ModelLabel
	}
	promptUsd := float64(u.InputTokens) * price.InputPrice
	completionUsd := float64(u.OutputTokens) * price.OutputPrice
	evt.Cost = &events.Cost{
		PromptUsd:     promptUsd,
		CompletionUsd: completionUsd,
		TotalUsd:      promptUsd + completionUsd,
		Currency:      costCurrencyUSD,
	}
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
