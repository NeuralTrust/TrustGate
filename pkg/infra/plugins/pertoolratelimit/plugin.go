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

package pertoolratelimit

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/go-redis/redis/v8"
)

const PluginName = "per_tool_rate_limiter"

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

type Plugin struct {
	redis    *redis.Client
	registry *adapter.Registry
	now      func() time.Time
}

type Option func(*Plugin)

func WithClock(now func() time.Time) Option {
	return func(p *Plugin) { p.now = now }
}

func New(redisClient *redis.Client, adapters *adapter.Registry, opts ...Option) *Plugin {
	p := &Plugin{
		redis:    redisClient,
		registry: adapters,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil {
		return okResult(), nil
	}
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
	}
	if in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
		return okResult(), nil
	}
	if p.registry == nil {
		return okResult(), nil
	}
	format := responseFormat(in.Request)
	if format == "" {
		return okResult(), nil
	}
	canonical, err := p.registry.DecodeResponseFor(in.Response.Body, adapter.Format(format))
	if err != nil || canonical == nil || len(canonical.ToolCalls) == 0 {
		return okResult(), nil
	}
	dimension, subject, err := in.Scope.Subject()
	if err != nil {
		return okResult(), nil
	}

	var violations []violation
	for _, tc := range canonical.ToolCalls {
		rule, ok := matchRule(cfg.Rules, tc.Name)
		if !ok {
			continue
		}
		behavior := rule.Behavior
		if behavior == "" {
			behavior = cfg.behaviorDefault()
		}
		var exceeded *windowConfig
		exceededTotal := 0
		for i := range rule.Windows {
			w := rule.Windows[i]
			secs := w.windowSeconds()
			key := fmt.Sprintf("pertoolrl:%s:%s:%s:%s:w%d", in.Config.ID, dimension, subject, tc.Name, i)
			total, err := recordScript.Run(ctx, p.redis, []string{key}, 1, secs).Int64()
			if err != nil {
				return nil, fmt.Errorf("per_tool_rate_limiter: record: %w", err)
			}
			if int(total) > w.Max && exceeded == nil {
				win := w
				exceeded = &win
				exceededTotal = int(total)
				setExtras(in.Event, PerToolRateLimiterData{
					Stage:         string(policy.StagePreResponse),
					CounterKey:    key,
					Tool:          tc.Name,
					Dimension:     dimension,
					Subject:       subject,
					WindowMax:     w.Max,
					WindowSeconds: secs,
					CurrentCount:  int(total),
					Behavior:      behavior,
					LimitExceeded: true,
				})
			}
		}
		if exceeded != nil {
			violations = append(violations, violation{tool: tc.Name, behavior: behavior, window: *exceeded, total: exceededTotal})
		}
	}
	for _, v := range violations {
		if v.behavior == behaviorReject {
			return p.reject(v.tool, v.window, v.total, dimension)
		}
	}
	return okResult(), nil
}

func (p *Plugin) reject(tool string, w windowConfig, total int, dimension string) (*appplugins.Result, error) {
	secs := w.windowSeconds()
	headers := make(map[string][]string)
	setLimitHeaders(headers, dimension, w.Max, int64(total), p.now().Add(time.Duration(secs)*time.Second))
	headers["X-RateLimit-Tool"] = []string{tool}
	headers["Retry-After"] = []string{strconv.Itoa(secs)}
	return nil, &appplugins.PluginError{
		StatusCode: http.StatusTooManyRequests,
		Message:    fmt.Sprintf("tool %q rate limit exceeded", tool),
		Headers:    headers,
	}
}

func setLimitHeaders(headers map[string][]string, dimension string, limit int, count int64, reset time.Time) {
	prefix := "X-RateLimit-" + dimension
	remaining := int64(limit) - count
	if remaining < 0 {
		remaining = 0
	}
	headers[prefix+"-Limit"] = []string{strconv.Itoa(limit)}
	headers[prefix+"-Remaining"] = []string{strconv.FormatInt(remaining, 10)}
	headers[prefix+"-Reset"] = []string{strconv.FormatInt(reset.Unix(), 10)}
}

func matchRule(rules []ruleConfig, name string) (*ruleConfig, bool) {
	for i := range rules {
		if ok, err := path.Match(rules[i].Tool, name); err == nil && ok {
			return &rules[i], true
		}
	}
	return nil, false
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

func setExtras(event *metrics.EventContext, data PerToolRateLimiterData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

type violation struct {
	tool     string
	behavior string
	window   windowConfig
	total    int
}

func okResult() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
