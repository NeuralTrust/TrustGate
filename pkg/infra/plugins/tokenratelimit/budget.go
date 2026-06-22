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
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/go-redis/redis/v8"
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
	return bestMatch(rules, model)
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

func windowsFor(cfg *config, base, model string) []budgetWindow {
	var windows []budgetWindow
	if cfg.PerModel {
		if r, ok := selectRule(cfg, model); ok {
			windows = append(windows, budgetWindow{
				key:       modelKey(base, r.Model),
				max:       counterMax(cfg, r.Max),
				windowSec: ruleWindowSeconds(cfg, r),
				model:     r.Model,
				label:     windowLabel(cfg, r.TimeWindow),
			})
		}
	}
	if cfg.Aggregate != nil {
		windows = append(windows, budgetWindow{
			key:       base,
			max:       counterMax(cfg, cfg.Aggregate.Max),
			windowSec: aggregateWindowSeconds(cfg),
			label:     windowLabel(cfg, cfg.Aggregate.TimeWindow),
			aggregate: true,
		})
	}
	return windows
}

func windowLabel(cfg *config, timeWindow string) string {
	if timeWindow != "" {
		return timeWindow
	}
	return cfg.Window.Unit
}

func counterMax(cfg *config, raw float64) float64 {
	if cfg.Unit == unitDollars {
		scaled := microUSD(raw)
		if scaled == 0 && raw > 0 {
			scaled = 1
		}
		return float64(scaled)
	}
	return raw
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
	cacheReads := 0
	if cfg.CountCacheReads {
		cacheReads = usage.CacheReadInputTokens
	}
	switch cfg.Counting {
	case countingInput:
		return usage.InputTokens + cacheReads
	case countingOutput:
		return usage.OutputTokens
	default:
		return usage.TotalTokens + cacheReads
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
	capTel *costCapTelemetry,
) (*appplugins.Result, error) {
	provider := ""
	if req != nil {
		provider = req.Provider
	}
	windows := windowsFor(cfg, base, model)
	if len(windows) == 0 {
		if capTel != nil {
			data := TokenRateLimiterData{
				Stage:    string(policy.StagePreRequest),
				Provider: provider,
				Model:    model,
			}
			capTel.apply(&data)
			setTokenExtras(event, data)
		}
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	consumedByWindow := make([]int64, len(windows))
	breachedIdx := -1
	for i := range windows {
		consumed, err := p.redis.Get(ctx, windows[i].key).Int64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("token_rate_limiter: read counter: %w", err)
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
	}
	if reportWindow.model != "" {
		data.Model = reportWindow.model
	}
	capTel.apply(&data)

	if !exceeded {
		setTokenExtras(event, data)
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}

	data.LimitExceeded = true
	setTokenExtras(event, data)
	appplugins.SetDecision(event, mode)

	return p.handleExceeded(ctx, cfg, reportWindow, scope, model, req, mode, headers)
}

func (p *Plugin) handleExceeded(
	ctx context.Context,
	cfg *config,
	w budgetWindow,
	scope, model string,
	req *infracontext.RequestContext,
	mode policy.Mode,
	headers map[string][]string,
) (*appplugins.Result, error) {
	if appplugins.Throttles(mode) {
		return p.throttle(ctx, w, headers)
	}
	if !appplugins.Blocks(mode) {
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}

	switch cfg.BehaviorOnExceeded {
	case behaviorThrottle:
		return p.throttle(ctx, w, headers)
	case behaviorAlertOnly:
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	case behaviorDowngradeModel:
		if _, hdr, ok := applyDowngrade(req, model, cfg.DowngradeTo); ok {
			return &appplugins.Result{StatusCode: http.StatusOK, Headers: mergeHeaderValues(headers, hdr)}, nil
		}
		return nil, budgetExceededError(cfg.Unit, scope, w.label, withBudgetMeta(headers, cfg.Unit, scope, w.label))
	default:
		return nil, budgetExceededError(cfg.Unit, scope, w.label, withBudgetMeta(headers, cfg.Unit, scope, w.label))
	}
}

func (p *Plugin) throttle(ctx context.Context, w budgetWindow, headers map[string][]string) (*appplugins.Result, error) {
	if err := appplugins.Throttle(ctx, time.Duration(w.windowSec)*time.Second); err != nil {
		return nil, err
	}
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
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

func (p *Plugin) accrue(
	ctx context.Context,
	cfg *config,
	base, model string,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	if resp == nil {
		return &appplugins.Result{}, nil
	}
	if cfg.Unit == unitDollars {
		return p.accrueDollars(ctx, cfg, base, model, req, resp, event)
	}

	tokens := countedTokens(cfg, p.extractUsage(req, resp))
	if tokens <= 0 {
		return &appplugins.Result{}, nil
	}

	windows := windowsFor(cfg, base, model)
	if len(windows) == 0 {
		return &appplugins.Result{}, nil
	}
	primary := windows[primaryWindowIndex(windows)]

	var primaryTotal int64
	for _, w := range windows {
		total, err := recordScript.Run(ctx, p.redis, []string{w.key}, int64(tokens), w.windowSec).Int64()
		if err != nil {
			return nil, fmt.Errorf("token_rate_limiter: record tokens: %w", err)
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
	headers := rateLimitHeaders(limit, remaining, p.resetSeconds(ctx, primary.key, primary.windowSec))
	headers["X-Tokens-Consumed"] = []string{strconv.Itoa(tokens)}

	provider := ""
	if req != nil {
		provider = req.Provider
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
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

func (p *Plugin) accrueDollars(
	ctx context.Context,
	cfg *config,
	base, model string,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	provider, requested := "", ""
	if req != nil {
		provider = req.Provider
		requested = req.RequestedModel
	}

	usage, servedModel := p.extractUsageAndModel(req, resp)

	inputRate, outputRate, found := p.priceFor(ctx, cfg, provider, model, servedModel, requested)
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
	cost := float64(billableInputTokens(cfg, usage))*inputRate + float64(usage.OutputTokens)*outputRate
	micros := microUSD(cost)
	if micros <= 0 {
		return &appplugins.Result{}, nil
	}

	windows := windowsFor(cfg, base, model)
	if len(windows) == 0 {
		return &appplugins.Result{}, nil
	}
	primary := windows[primaryWindowIndex(windows)]

	var primaryTotal int64
	for _, w := range windows {
		total, err := recordScript.Run(ctx, p.redis, []string{w.key}, micros, w.windowSec).Int64()
		if err != nil {
			return nil, fmt.Errorf("token_rate_limiter: record cost: %w", err)
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
