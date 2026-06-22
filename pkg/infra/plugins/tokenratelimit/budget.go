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
	"math"
	"net/http"
	"strconv"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/go-redis/redis/v8"
)

type budgetWindow struct {
	key       string
	max       float64
	windowSec int
	model     string
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
				max:       r.Max,
				windowSec: ruleWindowSeconds(cfg, r),
				model:     r.Model,
			})
		}
	}
	if cfg.Aggregate != nil {
		windows = append(windows, budgetWindow{
			key:       base,
			max:       cfg.Aggregate.Max,
			windowSec: aggregateWindowSeconds(cfg),
			aggregate: true,
		})
	}
	return windows
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

func countedTokens(counting string, usage *adapter.CanonicalUsage) int {
	if usage == nil {
		return 0
	}
	switch counting {
	case countingInput:
		return usage.InputTokens
	case countingOutput:
		return usage.OutputTokens
	default:
		return usage.TotalTokens
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
	base, model, provider string,
	mode policy.Mode,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	if cfg.Unit == unitDollars {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	windows := windowsFor(cfg, base, model)
	if len(windows) == 0 {
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

	limit := displayLimit(reportWindow.max)
	remaining := limit - int(reportConsumed)
	if remaining < 0 {
		remaining = 0
	}
	headers := rateLimitHeaders(limit, remaining, p.resetSeconds(ctx, reportWindow.key, reportWindow.windowSec))

	data := TokenRateLimiterData{
		Stage:           string(policy.StagePreRequest),
		CounterKey:      reportWindow.key,
		Provider:        provider,
		WindowUnit:      cfg.Window.Unit,
		WindowMax:       limit,
		TokensConsumed:  int(reportConsumed),
		TokensRemaining: remaining,
		Model:           model,
	}
	if reportWindow.model != "" {
		data.Model = reportWindow.model
	}

	if !exceeded {
		setTokenExtras(event, data)
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}

	data.LimitExceeded = true
	setTokenExtras(event, data)
	if event != nil {
		event.SetDecision(appplugins.DecisionForMode(mode))
	}

	switch {
	case appplugins.Throttles(mode):
		if err := appplugins.Throttle(ctx, time.Duration(reportWindow.windowSec)*time.Second); err != nil {
			return nil, err
		}
	case appplugins.Blocks(mode):
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Message:    fmt.Sprintf("token rate limit exceeded: consumed %d, limit %d", reportConsumed, limit),
			Headers:    headers,
		}
	}
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
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
		return &appplugins.Result{}, nil
	}

	tokens := countedTokens(cfg.Counting, p.extractUsage(req, resp))
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

func (p *Plugin) extractUsage(req *infracontext.RequestContext, resp *infracontext.ResponseContext) *adapter.CanonicalUsage {
	if resp == nil {
		return nil
	}
	if resp.Streaming {
		if req != nil && req.Metadata != nil {
			if cu, ok := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage); ok {
				return cu
			}
		}
		return nil
	}

	if len(resp.Body) == 0 || p.registry == nil {
		return nil
	}
	format := responseFormat(req)
	if format == "" {
		return nil
	}
	canonical, err := p.registry.DecodeResponseFor(resp.Body, adapter.Format(format))
	if err != nil || canonical == nil {
		return nil
	}
	return canonical.Usage
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
