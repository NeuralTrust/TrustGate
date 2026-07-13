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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/go-redis/redis/v8"
)

const PluginName = "per_tool_rate_limiter"

var countOnceScript = redis.NewScript(`
local set = redis.call('SET', KEYS[1], 1, 'NX', 'EX', tonumber(ARGV[1]))
if not set then
    return {}
end
local totals = {}
for i = 2, #KEYS do
    local total = redis.call('INCRBY', KEYS[i], 1)
    if redis.call('TTL', KEYS[i]) == -1 then
        redis.call('EXPIRE', KEYS[i], tonumber(ARGV[i]))
    end
    totals[#totals + 1] = total
end
return totals
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

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return true }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if p.redis == nil || p.registry == nil {
		return okResult(), nil
	}
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
	}
	dimension, subject, err := in.Scope.Subject()
	if err != nil {
		return okResult(), nil
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(ctx, cfg, in, dimension, subject)
	case policy.StagePreResponse:
		return p.preResponse(ctx, cfg, in, dimension, subject)
	default:
		return okResult(), nil
	}
}

func (p *Plugin) preRequest(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 {
		return okResult(), nil
	}
	format := wireFormat(in.Request)
	if format == "" {
		return okResult(), nil
	}
	canonical, err := p.registry.DecodeRequestFor(in.Request.Body, adapter.Format(format))
	if err != nil || canonical == nil {
		return okResult(), nil
	}
	if len(canonical.Messages) > 0 {
		if err := p.countExecuted(ctx, cfg, in, dimension, subject, canonical.Messages); err != nil {
			return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
		}
	}
	if len(canonical.Tools) == 0 {
		return okResult(), nil
	}

	strip := make(map[string]struct{})
	for i := range canonical.Tools {
		tool := canonical.Tools[i].Name
		if tool == "" {
			continue
		}
		rule, ok := matchRule(cfg.Rules, tool)
		if !ok {
			continue
		}
		behavior := effectiveBehavior(rule, cfg)
		if !p.enforcedAtRequest(behavior, canonical.Stream) {
			continue
		}
		ws, err := p.overLimit(ctx, in.Config.ID, dimension, subject, tool, rule)
		if err != nil {
			return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
		}
		if ws == nil {
			continue
		}
		setExtras(in.Event, p.data(policy.StagePreRequest, ws, tool, "", dimension, subject, behavior, true))
		if behavior == behaviorReject {
			return p.reject(ctx, tool, ws, dimension)
		}
		strip[tool] = struct{}{}
	}
	if len(strip) == 0 {
		return okResult(), nil
	}
	return p.stripTools(in.Request.Body, format, canonical, strip)
}

func (p *Plugin) enforcedAtRequest(behavior string, streaming bool) bool {
	switch behavior {
	case behaviorReject, behaviorStrip:
		return true
	case behaviorInject:
		return streaming
	default:
		return false
	}
}

func (p *Plugin) stripTools(
	originalBody []byte,
	format string,
	canonical *adapter.CanonicalRequest,
	strip map[string]struct{},
) (*appplugins.Result, error) {
	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: strip: %w", err)
	}
	fullEncoded, err := ad.EncodeRequest(canonical)
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: strip: %w", err)
	}
	kept := make([]adapter.CanonicalTool, 0, len(canonical.Tools))
	for i := range canonical.Tools {
		if _, drop := strip[canonical.Tools[i].Name]; drop {
			continue
		}
		kept = append(kept, canonical.Tools[i])
	}
	canonical.Tools = kept
	strippedEncoded, err := ad.EncodeRequest(canonical)
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: strip: %w", err)
	}
	body, err := graftChangedFields(originalBody, fullEncoded, strippedEncoded)
	if err != nil {
		body = strippedEncoded
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func graftChangedFields(original, fullEncoded, strippedEncoded []byte) ([]byte, error) {
	var orig, full, stripped map[string]json.RawMessage
	if err := json.Unmarshal(original, &orig); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fullEncoded, &full); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(strippedEncoded, &stripped); err != nil {
		return nil, err
	}
	for key, fullValue := range full {
		strippedValue, ok := stripped[key]
		if !ok {
			delete(orig, key)
			continue
		}
		if !bytes.Equal(fullValue, strippedValue) {
			orig[key] = strippedValue
		}
	}
	for key, strippedValue := range stripped {
		if _, ok := full[key]; !ok {
			orig[key] = strippedValue
		}
	}
	return json.Marshal(orig)
}

func (p *Plugin) preResponse(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
) (*appplugins.Result, error) {
	if in.Request == nil || in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
		return okResult(), nil
	}
	format := wireFormat(in.Request)
	if format == "" {
		return okResult(), nil
	}
	canonical, err := p.registry.DecodeResponseFor(in.Response.Body, adapter.Format(format))
	if err != nil || canonical == nil || len(canonical.ToolCalls) == 0 {
		return okResult(), nil
	}

	drop := make(map[int]string)
	for idx := range canonical.ToolCalls {
		tool := canonical.ToolCalls[idx].Name
		if tool == "" {
			continue
		}
		rule, ok := matchRule(cfg.Rules, tool)
		if !ok {
			continue
		}
		if effectiveBehavior(rule, cfg) != behaviorInject {
			continue
		}
		ws, err := p.overLimit(ctx, in.Config.ID, dimension, subject, tool, rule)
		if err != nil {
			return nil, fmt.Errorf("per_tool_rate_limiter: %w", err)
		}
		if ws == nil {
			continue
		}
		setExtras(in.Event, p.data(policy.StagePreResponse, ws, tool, "", dimension, subject, behaviorInject, true))
		drop[idx] = tool
	}
	if len(drop) == 0 {
		return okResult(), nil
	}
	return p.inject(canonical, format, drop)
}

func (p *Plugin) inject(
	canonical *adapter.CanonicalResponse,
	format string,
	drop map[int]string,
) (*appplugins.Result, error) {
	ad, err := p.registry.GetAdapter(adapter.Format(format))
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: inject: %w", err)
	}
	kept := make([]adapter.CanonicalToolCall, 0, len(canonical.ToolCalls))
	for idx := range canonical.ToolCalls {
		tc := canonical.ToolCalls[idx]
		if tool, ok := drop[idx]; ok {
			canonical.Content += fmt.Sprintf(rateLimitTemplate, tool, tc.ID)
			continue
		}
		kept = append(kept, tc)
	}
	canonical.ToolCalls = kept
	if len(canonical.ToolCalls) == 0 {
		canonical.FinishReason = "stop"
	}
	body, err := ad.EncodeResponse(canonical)
	if err != nil {
		return nil, fmt.Errorf("per_tool_rate_limiter: inject: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, Body: body, StopUpstream: true}, nil
}

func toolCallNames(messages []adapter.CanonicalMessage) map[string]string {
	names := make(map[string]string)
	for i := range messages {
		for j := range messages[i].ToolCalls {
			tc := messages[i].ToolCalls[j]
			if tc.ID == "" || tc.Name == "" {
				continue
			}
			names[tc.ID] = tc.Name
		}
	}
	return names
}

func latestToolCallTurn(messages []adapter.CanonicalMessage) int {
	last := -1
	for i := range messages {
		if len(messages[i].ToolCalls) > 0 {
			last = i
		}
	}
	return last
}

func (p *Plugin) countExecuted(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject string,
	messages []adapter.CanonicalMessage,
) error {
	turn := latestToolCallTurn(messages)
	if turn < 0 {
		return nil
	}
	names := toolCallNames(messages)
	for i := turn + 1; i < len(messages); i++ {
		if messages[i].Role != "tool" || messages[i].ToolCallID == "" {
			continue
		}
		tool, ok := names[messages[i].ToolCallID]
		if !ok || tool == "" {
			continue
		}
		rule, ok := matchRule(cfg.Rules, tool)
		if !ok {
			continue
		}
		if err := p.recordOnce(ctx, cfg, in, dimension, subject, tool, messages[i].ToolCallID, rule); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) recordOnce(
	ctx context.Context,
	cfg *config,
	in appplugins.ExecInput,
	dimension, subject, tool, toolCallID string,
	rule *ruleConfig,
) error {
	keys := make([]string, 0, len(rule.Windows)+1)
	keys = append(keys, dedupeKey(in.Config.ID, dimension, subject, toolCallID))
	args := make([]any, 0, len(rule.Windows)+1)
	args = append(args, int(largestWindow(rule)/time.Second))
	for i := range rule.Windows {
		keys = append(keys, counterKey(in.Config.ID, dimension, subject, tool, i))
		args = append(args, rule.Windows[i].windowSeconds())
	}
	res, err := countOnceScript.Run(ctx, p.redis, keys, args...).Result()
	if err != nil {
		return err
	}
	totals, ok := res.([]any)
	if !ok || len(totals) == 0 {
		return nil
	}
	behavior := effectiveBehavior(rule, cfg)
	for i := range rule.Windows {
		if i >= len(totals) {
			break
		}
		total, _ := totals[i].(int64)
		w := rule.Windows[i]
		key := counterKey(in.Config.ID, dimension, subject, tool, i)
		ws := &windowState{key: key, window: w, total: int(total)}
		setExtras(in.Event, p.data(policy.StagePreRequest, ws, tool, toolCallID, dimension, subject, behavior, int(total) >= w.Max))
	}
	return nil
}

func (p *Plugin) overLimit(
	ctx context.Context,
	configID, dimension, subject, tool string,
	rule *ruleConfig,
) (*windowState, error) {
	for i := range rule.Windows {
		key := counterKey(configID, dimension, subject, tool, i)
		v, err := p.redis.Get(ctx, key).Int64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return nil, err
		}
		if int(v) >= rule.Windows[i].Max {
			return &windowState{key: key, window: rule.Windows[i], total: int(v)}, nil
		}
	}
	return nil, nil
}

func (p *Plugin) reject(ctx context.Context, tool string, ws *windowState, dimension string) (*appplugins.Result, error) {
	secs := ws.window.windowSeconds()
	reset := p.now().Add(time.Duration(secs) * time.Second)
	if ttl, err := p.redis.TTL(ctx, ws.key).Result(); err == nil && ttl > 0 {
		secs = int((ttl + time.Second - 1) / time.Second)
		reset = p.now().Add(ttl)
	}
	headers := make(map[string][]string)
	setLimitHeaders(headers, dimension, ws.window.Max, int64(ws.total), reset)
	headers["X-RateLimit-Tool"] = []string{tool}
	headers["Retry-After"] = []string{strconv.Itoa(secs)}
	return nil, &appplugins.PluginError{
		StatusCode: http.StatusTooManyRequests,
		Message:    fmt.Sprintf("tool %q rate limit exceeded", tool),
		Headers:    headers,
	}
}

func (p *Plugin) data(
	stage policy.Stage,
	ws *windowState,
	tool, toolCallID, dimension, subject, behavior string,
	exceeded bool,
) PerToolRateLimiterData {
	return PerToolRateLimiterData{
		Stage:         string(stage),
		CounterKey:    ws.key,
		Tool:          tool,
		ToolCallID:    toolCallID,
		Dimension:     dimension,
		Subject:       subject,
		WindowMax:     ws.window.Max,
		WindowSeconds: ws.window.windowSeconds(),
		CurrentCount:  ws.total,
		Behavior:      behavior,
		LimitExceeded: exceeded,
	}
}

type windowState struct {
	key    string
	window windowConfig
	total  int
}

func counterKey(configID, dimension, subject, tool string, window int) string {
	return fmt.Sprintf("pertoolrl:%s:%s:%s:%s:w%d", configID, dimension, subject, tool, window)
}

func dedupeKey(configID, dimension, subject, toolCallID string) string {
	return fmt.Sprintf("pertoolrl:dedupe:%s:%s:%s:%s", configID, dimension, subject, toolCallID)
}

func largestWindow(rule *ruleConfig) time.Duration {
	largest := 0
	for i := range rule.Windows {
		if s := rule.Windows[i].windowSeconds(); s > largest {
			largest = s
		}
	}
	return time.Duration(largest) * time.Second
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
		if matchToolPattern(rules[i].Tool, name) {
			return &rules[i], true
		}
	}
	return nil, false
}

func matchToolPattern(pattern, name string) bool {
	const sentinel = "\x00"
	p := strings.ReplaceAll(pattern, "/", sentinel)
	n := strings.ReplaceAll(name, "/", sentinel)
	ok, err := path.Match(p, n)
	return err == nil && ok
}

func effectiveBehavior(rule *ruleConfig, cfg *config) string {
	if rule.Behavior != "" {
		return rule.Behavior
	}
	return cfg.behaviorDefault()
}

func wireFormat(req *infracontext.RequestContext) string {
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

func okResult() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
