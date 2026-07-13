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
	"fmt"
	"net/http"
	"strconv"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/go-redis/redis/v8"
)

const PluginName = "token_rate_limiter"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	redis    *redis.Client
	registry *adapter.Registry
	pricing  appcatalog.PricingResolver
}

func New(redisClient *redis.Client, registry *adapter.Registry, pricing appcatalog.PricingResolver) *Plugin {
	return &Plugin{redis: redisClient, registry: registry, pricing: pricing}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil || in.Request.Provider == "" {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("token_rate_limiter: %w", err)
	}

	dimension, subject, err := in.Scope.Subject()
	if err != nil {
		return nil, fmt.Errorf("token_rate_limiter: %w", err)
	}
	base := aggregateKey(in.Config.ID, dimension, subject, in.Request.HeaderValue(cfg.GroupByHeader))

	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(ctx, cfg, base, dimension, in.Request, in.Mode, in.Event)
	case policy.StagePostResponse:
		return p.postResponse(ctx, cfg, base, in.Request, in.Response, in.Event)
	default:
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
}

func (p *Plugin) preRequest(
	ctx context.Context,
	cfg *config,
	base, scope string,
	req *infracontext.RequestContext,
	mode policy.Mode,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	model := modelFor(req)
	var capTel *llmcost.Telemetry
	var downgradeHeaders map[string][]string
	var downgradeBody []byte
	if cfg.CostCap != nil && cfg.CostCap.Enabled {
		dec := llmcost.Decide(ctx, p.pricing, cfg.CustomPricing, cfg.CostCap, req.Provider, model, req.RequestedModel)
		capTel = llmcost.TelemetryFrom(dec)
		if dec.Kind == llmcost.DecisionViolation {
			appplugins.SetDecision(event, mode)
			if appplugins.Blocks(mode) && !appplugins.Throttles(mode) {
				if cfg.CostCap.BehaviorOnViolation == llmcost.BehaviorDowngrade {
					newModel, body, hdr, ok := llmcost.ApplyDowngrade(req, model, cfg.CostCap.DowngradeTo)
					if !ok {
						return nil, llmcost.CostCapError(dec)
					}
					model = newModel
					downgradeBody = body
					downgradeHeaders = hdr
				} else {
					return nil, llmcost.CostCapError(dec)
				}
			}
		}
	}

	res, err := p.budgetGate(ctx, cfg, base, model, scope, req, mode, event, capTel)
	if err != nil {
		return nil, err
	}
	if len(downgradeHeaders) > 0 {
		res.Headers = mergeHeaderValues(res.Headers, downgradeHeaders)
	}
	if downgradeBody != nil && res.RequestBody == nil {
		res.RequestBody = downgradeBody
	}
	return res, nil
}

func mergeHeaderValues(dst, src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string][]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (p *Plugin) postResponse(
	ctx context.Context,
	cfg *config,
	base string,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	return p.accrue(ctx, cfg, base, modelFor(req), req, resp, event)
}

func setTokenExtras(event *metrics.EventContext, data TokenRateLimiterData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func applyCostCapTelemetry(data *TokenRateLimiterData, t *llmcost.Telemetry) {
	if t == nil {
		return
	}
	data.CostCapViolation = t.Violation
	data.UnknownModel = t.Unknown
	data.InputPricePer1k = t.InputPrice
	data.OutputPricePer1k = t.OutputPrice
	data.MaxInputPer1k = t.MaxInput
	data.MaxOutputPer1k = t.MaxOutput
}

func (p *Plugin) resetSeconds(ctx context.Context, counterKey string, fallbackSec int) int {
	ttl, err := p.redis.TTL(ctx, counterKey).Result()
	if err == nil && ttl > 0 {
		return int(ttl / time.Second)
	}
	return fallbackSec
}

func rateLimitHeaders(limit, remaining, resetSeconds int) map[string][]string {
	return map[string][]string{
		"X-Ratelimit-Limit-Tokens":     {strconv.Itoa(limit)},
		"X-Ratelimit-Remaining-Tokens": {strconv.Itoa(remaining)},
		"X-Ratelimit-Reset-Tokens":     {strconv.Itoa(resetSeconds) + "s"},
	}
}
