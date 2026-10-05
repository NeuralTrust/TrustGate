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

package tokenratelimit

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/redis/go-redis/v9"
)

type budgetWindow struct {
	key       string
	max       float64
	windowSec int
	model     string
	label     string
	aggregate bool
}

func selectRule(cfg *config, model string) (budgetRule, bool) {
	if len(cfg.Rules) == 0 {
		return budgetRule{}, false
	}
	rules := make(map[string]budgetRule, len(cfg.Rules))
	for _, r := range cfg.Rules {
		rules[r.Model] = r
	}
	return llmcost.BestMatch(rules, model)
}

func aggregateWindowSeconds(cfg *config) int {
	if cfg.Aggregate != nil && cfg.Aggregate.TimeWindow != "" {
		if secs, err := parseWindow(cfg.Aggregate.TimeWindow); err == nil {
			return secs
		}
	}
	return cfg.windowSeconds()
}

func ruleWindowSeconds(cfg *config, r budgetRule) int {
	if r.TimeWindow != "" {
		if secs, err := parseWindow(r.TimeWindow); err == nil {
			return secs
		}
	}
	return cfg.windowSeconds()
}

func windowsFor(cfg *config, base, model string, now time.Time) []budgetWindow {
	var windows []budgetWindow
	if cfg.PerModel {
		if r, ok := selectRule(cfg, model); ok {
			key, secs := periodWindow(base, r.TimeWindow, now, ruleWindowSeconds(cfg, r))
			windows = append(windows, budgetWindow{
				key:       modelKey(key, r.Model),
				max:       counterMax(cfg, r.Max),
				windowSec: secs,
				model:     r.Model,
				label:     windowLabel(cfg, r.TimeWindow),
			})
		}
	}
	if cfg.Aggregate != nil {
		key, secs := periodWindow(base, cfg.Aggregate.TimeWindow, now, aggregateWindowSeconds(cfg))
		windows = append(windows, budgetWindow{
			key:       key,
			max:       counterMax(cfg, cfg.Aggregate.Max),
			windowSec: secs,
			label:     windowLabel(cfg, cfg.Aggregate.TimeWindow),
			aggregate: true,
		})
	}
	return windows
}

func periodWindow(base, timeWindow string, now time.Time, rollingSeconds int) (string, int) {
	period, ttl, ok := calendarPeriod(timeWindow, now)
	if !ok {
		return base, rollingSeconds
	}
	return periodKey(base, period), ttl
}

func windowLabel(cfg *config, timeWindow string) string {
	if timeWindow != "" {
		return timeWindow
	}
	return cfg.Window.Unit
}

func counterMax(cfg *config, raw float64) float64 {
	if cfg.Unit == unitDollars {
		scaled := llmcost.MicroUSD(raw)
		if scaled == 0 && raw > 0 {
			scaled = 1
		}
		return float64(scaled)
	}
	return raw
}

func billableInputTokens(cfg *config, usage *adapter.CanonicalUsage) int {
	if usage == nil {
		return 0
	}
	if cfg.CountCacheReads {
		return usage.InputTokens
	}
	return usage.InputTokens - usage.CachedInputTokens
}

func primaryWindowIndex(windows []budgetWindow) int {
	for i := range windows {
		if windows[i].aggregate {
			return i
		}
	}
	return 0
}

func exceeds(consumed int64, max float64) bool {
	return float64(consumed) >= max
}

func displayLimit(max float64) int {
	return int(math.Round(max))
}

func countedTokens(cfg *config, usage *adapter.CanonicalUsage) int {
	if usage == nil {
		return 0
	}
	discount := 0
	if !cfg.CountCacheReads {
		discount = usage.CachedInputTokens
	}
	switch cfg.Counting {
	case countingInput:
		return usage.InputTokens - discount
	case countingOutput:
		return usage.OutputTokens
	default:
		return usage.TotalTokens - discount
	}
}

func modelFor(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if len(req.Body) > 0 {
		if m, err := adapter.ExtractModel(req.Body); err == nil && m != "" {
			return m
		}
	}
	return req.RequestedModel
}

func (p *Plugin) budgetGate(
	ctx context.Context,
	cfg *config,
	base, model, scope string,
	req *infracontext.RequestContext,
	mode policy.Mode,
	event *metrics.EventContext,
	capTel *llmcost.Telemetry,
) (*appplugins.Result, error) {
	provider := ""
	if req != nil {
		provider = req.Provider
	}
	windows := windowsFor(cfg, base, model, p.now())
	if len(windows) == 0 {
		if capTel != nil {
			data := TokenRateLimiterData{
				Stage:    string(policy.StagePreRequest),
				Provider: provider,
				Model:    model,
			}
			applyCostCapTelemetry(&data, capTel)
			setTokenExtras(event, data)
		}
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	unpriced := cfg.Partition == partitionKey && cfg.Unit == unitDollars && !p.priced(ctx, cfg, req, model)
	if unpriced {
		appplugins.SetDecision(event, mode)
		if appplugins.Blocks(mode) {
			data := TokenRateLimiterData{
				Stage:    string(policy.StagePreRequest),
				Provider: provider,
				Model:    model,
				Unit:     unitDollars,
				Unpriced: true,
			}
			applyCostCapTelemetry(&data, capTel)
			setTokenExtras(event, data)
			return nil, modelUnpricedError(model)
		}
	}

	consumedByWindow := make([]int64, len(windows))
	breachedIdx := -1
	for i := range windows {
		consumed, err := p.redis.Get(ctx, windows[i].key).Int64()
		if err != nil && !errors.Is(err, redis.Nil) {
			// The window loop has not yet determined which counter is
			// reported (that only happens once every window's read
			// succeeds), so there is no reportWindow/reportConsumed to carry
			// here — but provider, model and cost-cap telemetry are already
			// known and must not be lost to a bare failure record.
			failData := TokenRateLimiterData{Provider: provider, Model: model, Unpriced: unpriced}
			if windows[i].model != "" {
				failData.Model = windows[i].model
			}
			applyCostCapTelemetry(&failData, capTel)
			if cfg.Partition == partitionKey && appplugins.Blocks(mode) && ctx.Err() == nil {
				return nil, failClosed(ctx, mode, event, failData, "read_counter", err)
			}
			return p.counterUnavailable(ctx, policy.StagePreRequest, mode, event, failData, "read_counter", err)
		}
		consumedByWindow[i] = consumed
		if breachedIdx == -1 && exceeds(consumed, windows[i].max) {
			breachedIdx = i
		}
	}

	exceeded := breachedIdx != -1
	reportIdx := breachedIdx
	if !exceeded {
		reportIdx = primaryWindowIndex(windows)
	}
	reportWindow := windows[reportIdx]
	reportConsumed := consumedByWindow[reportIdx]

	headers := p.budgetHeaders(ctx, cfg, reportWindow, reportConsumed, scope)

	data := TokenRateLimiterData{
		Stage:           string(policy.StagePreRequest),
		CounterKey:      reportWindow.key,
		Provider:        provider,
		WindowUnit:      cfg.Window.Unit,
		WindowMax:       displayLimit(reportWindow.max),
		TokensConsumed:  int(reportConsumed),
		TokensRemaining: tokensRemaining(reportWindow.max, reportConsumed),
		Model:           model,
		Unit:            cfg.Unit,
		Unpriced:        unpriced,
	}
	if reportWindow.model != "" {
		data.Model = reportWindow.model
	}
	applyCostCapTelemetry(&data, capTel)

	if !exceeded {
		setTokenExtras(event, data)
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}

	data.LimitExceeded = true
	setTokenExtras(event, data)
	appplugins.SetDecision(event, mode)

	return p.handleExceeded(cfg, reportWindow, scope, model, req, mode, headers)
}

func (p *Plugin) handleExceeded(
	cfg *config,
	w budgetWindow,
	scope, model string,
	req *infracontext.RequestContext,
	mode policy.Mode,
	headers map[string][]string,
) (*appplugins.Result, error) {
	if !appplugins.Blocks(mode) {
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}

	switch cfg.BehaviorOnExceeded {
	case behaviorDowngradeModel:
		if _, body, hdr, ok := llmcost.ApplyDowngrade(req, model, cfg.DowngradeTo); ok {
			return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body, Headers: mergeHeaderValues(headers, hdr)}, nil
		}
		return nil, budgetExceededError(cfg.Unit, scope, w.label, withBudgetMeta(headers, cfg.Unit, scope, w.label))
	default:
		return nil, budgetExceededError(cfg.Unit, scope, w.label, withBudgetMeta(headers, cfg.Unit, scope, w.label))
	}
}

// counterUnavailable turns a counter-store (Redis) failure into a pass-through
// outcome via the shared appplugins.HandleCounterFailure: unlike a budget
// actually exceeded, this always fails open, whatever mode is in play
// (subject to the ctx exception below) — our own infrastructure fails open in
// every mode, including enforce, unlike a third-party guardrail. data is
// whatever the caller already knows (provider, model, cost-cap telemetry);
// this only adds FailureReason/FailureDetail on top of it, so that context is
// not lost the way a bare TokenRateLimiterData would lose it.
//
// A ctx the caller itself canceled (or let deadline out) is not a
// counter-store outage — HandleCounterFailure reports that back as a non-nil
// error, and this returns it unchanged: no failed_open, no
// counter_unavailable, no Warn, exactly the pre-RUN-1675 behavior.
func (p *Plugin) counterUnavailable(
	ctx context.Context,
	stage policy.Stage,
	mode policy.Mode,
	event *metrics.EventContext,
	data TokenRateLimiterData,
	detail string,
	err error,
) (*appplugins.Result, error) {
	result, ferr := appplugins.HandleCounterFailure(appplugins.CounterFailure{
		Ctx:    ctx,
		Plugin: PluginName,
		Stage:  stage,
		Mode:   mode,
		Detail: detail,
		Err:    err,
		Event:  event,
	})
	if ferr != nil {
		return nil, ferr
	}
	data.Stage = string(stage)
	data.FailureReason = string(appplugins.FailureCounterUnavailable)
	data.FailureDetail = detail
	setTokenExtras(event, data)
	return result, nil
}

func failClosed(
	ctx context.Context,
	mode policy.Mode,
	event *metrics.EventContext,
	data TokenRateLimiterData,
	detail string,
	err error,
) *appplugins.PluginError {
	slog.WarnContext(ctx, "counter store call failed",
		slog.String("plugin", PluginName),
		slog.String("stage", string(policy.StagePreRequest)),
		slog.String("mode", string(mode)),
		slog.String("reason", string(appplugins.FailureCounterUnavailable)),
		slog.String("decision", decisionFailedClosed),
		slog.String("detail", detail),
		slog.Any("error", err))
	data.Stage = string(policy.StagePreRequest)
	data.FailureReason = string(appplugins.FailureCounterUnavailable)
	data.FailureDetail = detail
	setTokenExtras(event, data)
	appplugins.SetDecisionFromOutcome(event, decisionFailedClosed)
	return budgetUnavailableError()
}

func (p *Plugin) budgetHeaders(ctx context.Context, cfg *config, w budgetWindow, consumed int64, scope string) map[string][]string {
	reset := p.resetSeconds(ctx, w.key, w.windowSec)
	if cfg.Unit == unitDollars {
		return dollarBudgetHeaders(int64(math.Round(w.max)), consumed, scope, w.label, reset)
	}
	limit := displayLimit(w.max)
	remaining := limit - int(consumed)
	if remaining < 0 {
		remaining = 0
	}
	return rateLimitHeaders(limit, remaining, reset)
}

func tokensRemaining(max float64, consumed int64) int {
	r := displayLimit(max) - int(consumed)
	if r < 0 {
		return 0
	}
	return r
}

// accrue charges the windows once the answer is known. It reports through the
// event only: the post-response stage runs after the response has been sent, so
// any header it returned would be written to a snapshot nobody reads.
func (p *Plugin) accrue(
	ctx context.Context,
	cfg *config,
	base, model string,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	mode policy.Mode,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	if resp == nil {
		return &appplugins.Result{}, nil
	}
	if cfg.Unit == unitDollars {
		return p.accrueDollars(ctx, cfg, base, model, req, resp, mode, event)
	}

	tokens := countedTokens(cfg, p.extractUsage(req, resp))
	if tokens <= 0 {
		return &appplugins.Result{}, nil
	}

	windows := windowsFor(cfg, base, model, p.now())
	if len(windows) == 0 {
		return &appplugins.Result{}, nil
	}
	primary := windows[primaryWindowIndex(windows)]

	provider := ""
	if req != nil {
		provider = req.Provider
	}
	var primaryTotal int64
	for _, w := range windows {
		total, err := recordScript.Run(ctx, p.redis, []string{w.key}, int64(tokens), w.windowSec).Int64()
		if err != nil {
			failData := TokenRateLimiterData{Provider: provider, Model: model, TokensActual: tokens}
			return p.counterUnavailable(ctx, policy.StagePostResponse, mode, event, failData, "record_tokens", err)
		}
		if w.key == primary.key {
			primaryTotal = total
		}
	}

	limit := displayLimit(primary.max)
	remaining := limit - int(primaryTotal)
	if remaining < 0 {
		remaining = 0
	}

	setTokenExtras(event, TokenRateLimiterData{
		Stage:           string(policy.StagePostResponse),
		CounterKey:      primary.key,
		Provider:        provider,
		WindowUnit:      cfg.Window.Unit,
		WindowMax:       limit,
		TokensConsumed:  int(primaryTotal),
		TokensActual:    tokens,
		TokensRemaining: remaining,
		Model:           model,
	})
	return &appplugins.Result{StatusCode: http.StatusOK}, nil
}

func (p *Plugin) accrueDollars(
	ctx context.Context,
	cfg *config,
	base, model string,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	mode policy.Mode,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	provider, requested := "", ""
	if req != nil {
		provider = req.Provider
		requested = req.RequestedModel
	}

	usage, servedModel := p.extractUsageAndModel(req, resp)

	var overlay *llmcost.RegistryRates
	if req != nil {
		overlay = llmcost.RatesFromDomain(req.RegistryPricing)
	}
	rates, found := llmcost.Resolve(ctx, p.pricing, cfg.CustomPricing, overlay, provider, model, servedModel, requested)
	if !found {
		slog.Warn("token_rate_limiter: unpriced model in dollar budget, accruing zero",
			slog.String("provider", provider),
			slog.String("model", model),
			slog.String("served_model", servedModel))
		setTokenExtras(event, TokenRateLimiterData{
			Stage:    string(policy.StagePostResponse),
			Provider: provider,
			Model:    model,
			Unit:     unitDollars,
			Unpriced: true,
		})
		return &appplugins.Result{}, nil
	}

	if usage == nil {
		return &appplugins.Result{}, nil
	}
	prompt, completion := rates.CostUSD(usage)
	cost := prompt + completion
	micros := llmcost.MicroUSD(cost)
	if micros <= 0 {
		return &appplugins.Result{}, nil
	}

	windows := windowsFor(cfg, base, model, p.now())
	if len(windows) == 0 {
		return &appplugins.Result{}, nil
	}
	primary := windows[primaryWindowIndex(windows)]

	var primaryTotal int64
	for _, w := range windows {
		total, err := recordScript.Run(ctx, p.redis, []string{w.key}, micros, w.windowSec).Int64()
		if err != nil {
			failData := TokenRateLimiterData{
				Provider:     provider,
				Model:        model,
				Unit:         unitDollars,
				CostMicroUSD: micros,
			}
			return p.counterUnavailable(ctx, policy.StagePostResponse, mode, event, failData, "record_cost", err)
		}
		if w.key == primary.key {
			primaryTotal = total
		}
	}

	setTokenExtras(event, TokenRateLimiterData{
		Stage:            string(policy.StagePostResponse),
		CounterKey:       primary.key,
		Provider:         provider,
		Model:            model,
		Unit:             unitDollars,
		CostMicroUSD:     micros,
		ConsumedMicroUSD: primaryTotal,
	})
	return &appplugins.Result{StatusCode: http.StatusOK}, nil
}

func (p *Plugin) extractUsage(req *infracontext.RequestContext, resp *infracontext.ResponseContext) *adapter.CanonicalUsage {
	usage, _ := p.extractUsageAndModel(req, resp)
	return usage
}

func (p *Plugin) extractUsageAndModel(req *infracontext.RequestContext, resp *infracontext.ResponseContext) (*adapter.CanonicalUsage, string) {
	if resp == nil {
		return nil, ""
	}
	if resp.Streaming {
		if req != nil && req.Metadata != nil {
			if cu, ok := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage); ok {
				return cu, ""
			}
		}
		return nil, ""
	}

	if len(resp.Body) == 0 || p.registry == nil {
		return nil, ""
	}
	format := responseFormat(req)
	if format == "" {
		return nil, ""
	}
	canonical, err := p.registry.DecodeResponseFor(resp.Body, adapter.Format(format))
	if err != nil || canonical == nil {
		return nil, ""
	}
	return canonical.Usage, canonical.Model
}

func responseFormat(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.SourceFormat != "" {
		return req.SourceFormat
	}
	return req.Provider
}
