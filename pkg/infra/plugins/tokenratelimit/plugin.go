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

// PluginName is the catalog name used in policy configuration.
const PluginName = "token_rate_limiter"

const counterKeyPrefix = "trl"

// recordScript atomically increments the consumed-token counter and sets the
// TTL only on the first write, so the window resets when the key expires.
var recordScript = redis.NewScript(`
local key        = KEYS[1]
local tokens     = tonumber(ARGV[1])
local window_sec = tonumber(ARGV[2])
local total = redis.call('INCRBY', key, tokens)
if redis.call('TTL', key) == -1 then
    redis.call('EXPIRE', key, window_sec)
end
return total
`)

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin enforces a token budget per identifier over a fixed time window.
type Plugin struct {
	redis    *redis.Client
	registry *adapter.Registry
}

// New builds a token rate limiter backed by Redis and the provider adapter
// registry (used to count tokens in upstream responses).
func New(redisClient *redis.Client, registry *adapter.Registry) *Plugin {
	return &Plugin{redis: redisClient, registry: registry}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	// Token limiting only applies to provider (LLM) traffic.
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
	counterKey := fmt.Sprintf("%s:%s:%s:%s", counterKeyPrefix, in.Config.ID, dimension, subject)
	if group := in.Request.HeaderValue(cfg.GroupByHeader); group != "" {
		counterKey += ":hdr:" + group
	}

	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(ctx, cfg, counterKey, in.Request.Provider, in.Mode, in.Event)
	case policy.StagePostResponse:
		return p.postResponse(ctx, cfg, counterKey, in.Request, in.Response, in.Event)
	default:
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
}

func (p *Plugin) preRequest(
	ctx context.Context,
	cfg *config,
	counterKey string,
	provider string,
	mode policy.Mode,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	consumed, err := p.redis.Get(ctx, counterKey).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("token_rate_limiter: read counter: %w", err)
	}

	remaining := cfg.Window.Max - int(consumed)
	if remaining < 0 {
		remaining = 0
	}
	headers := rateLimitHeaders(cfg.Window.Max, remaining, p.resetSeconds(ctx, counterKey, cfg))

	data := TokenRateLimiterData{
		Stage:           string(policy.StagePreRequest),
		CounterKey:      counterKey,
		Provider:        provider,
		WindowUnit:      cfg.Window.Unit,
		WindowMax:       cfg.Window.Max,
		TokensConsumed:  int(consumed),
		TokensRemaining: remaining,
	}

	if consumed >= int64(cfg.Window.Max) {
		data.LimitExceeded = true
		setTokenExtras(event, data)
		if event != nil {
			event.SetDecision(appplugins.DecisionForMode(mode))
		}
		switch {
		case appplugins.Throttles(mode):
			if err := appplugins.Throttle(ctx, throttleDelay(cfg)); err != nil {
				return nil, err
			}
		case appplugins.Blocks(mode):
			return nil, &appplugins.PluginError{
				StatusCode: http.StatusTooManyRequests,
				Message:    fmt.Sprintf("token rate limit exceeded: consumed %d, limit %d", consumed, cfg.Window.Max),
				Headers:    headers,
			}
		}
		return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
	}
	setTokenExtras(event, data)
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

func throttleDelay(cfg *config) time.Duration {
	return time.Duration(cfg.windowSeconds()) * time.Second
}

func (p *Plugin) postResponse(
	ctx context.Context,
	cfg *config,
	counterKey string,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	event *metrics.EventContext,
) (*appplugins.Result, error) {
	if resp == nil {
		return &appplugins.Result{}, nil
	}

	tokens := p.extractTokens(req, resp)
	if tokens == 0 {
		return &appplugins.Result{}, nil
	}

	total, err := recordScript.Run(ctx, p.redis, []string{counterKey}, tokens, cfg.windowSeconds()).Int64()
	if err != nil {
		return nil, fmt.Errorf("token_rate_limiter: record tokens: %w", err)
	}

	remaining := cfg.Window.Max - int(total)
	if remaining < 0 {
		remaining = 0
	}
	headers := rateLimitHeaders(cfg.Window.Max, remaining, p.resetSeconds(ctx, counterKey, cfg))
	headers["X-Tokens-Consumed"] = []string{strconv.Itoa(tokens)}

	provider := ""
	if req != nil {
		provider = req.Provider
	}
	setTokenExtras(event, TokenRateLimiterData{
		Stage:           string(policy.StagePostResponse),
		CounterKey:      counterKey,
		Provider:        provider,
		WindowUnit:      cfg.Window.Unit,
		WindowMax:       cfg.Window.Max,
		TokensConsumed:  int(total),
		TokensActual:    tokens,
		TokensRemaining: remaining,
	})
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

func setTokenExtras(event *metrics.EventContext, data TokenRateLimiterData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

// extractTokens reads the total tokens an upstream response consumed. Streaming
// responses are read from the usage observed during the stream; non-streaming
// responses are decoded from the body.
func (p *Plugin) extractTokens(req *infracontext.RequestContext, resp *infracontext.ResponseContext) int {
	if resp.Streaming {
		if req != nil && req.Metadata != nil {
			if cu, ok := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage); ok && cu != nil {
				return cu.TotalTokens
			}
		}
		return 0
	}

	if len(resp.Body) == 0 || p.registry == nil {
		return 0
	}
	format := responseFormat(req)
	if format == "" {
		return 0
	}
	canonical, err := p.registry.DecodeResponseFor(resp.Body, adapter.Format(format))
	if err != nil || canonical == nil || canonical.Usage == nil {
		return 0
	}
	return canonical.Usage.TotalTokens
}

// responseFormat returns the wire format of the response body. The forwarder
// adapts upstream responses back to the client's source format, so that is the
// format to decode; provider is the fallback.
func responseFormat(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.SourceFormat != "" {
		return req.SourceFormat
	}
	return req.Provider
}

func (p *Plugin) resetSeconds(ctx context.Context, counterKey string, cfg *config) int {
	ttl, err := p.redis.TTL(ctx, counterKey).Result()
	if err == nil && ttl > 0 {
		return int(ttl / time.Second)
	}
	return cfg.windowSeconds()
}

func rateLimitHeaders(limit, remaining, resetSeconds int) map[string][]string {
	return map[string][]string{
		"X-Ratelimit-Limit-Tokens":     {strconv.Itoa(limit)},
		"X-Ratelimit-Remaining-Tokens": {strconv.Itoa(remaining)},
		"X-Ratelimit-Reset-Tokens":     {strconv.Itoa(resetSeconds) + "s"},
	}
}
