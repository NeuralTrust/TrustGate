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
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	return newTestPluginWithPricing(t, nil)
}

func newTestPluginWithPricing(t *testing.T, pricing appcatalog.PricingResolver) *Plugin {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, adapter.NewRegistry(), pricing)
}

func input(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Config:   policy.PluginConfig{ID: "tk-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:    appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request:  req,
		Response: resp,
	}
}

func TestPlugin_Stages(t *testing.T) {
	p := New(nil, nil, nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, p.SupportedStages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{name: "valid", settings: map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}},
		{name: "zero max", settings: map[string]any{"window": map[string]any{"unit": "minute", "max": 0}}, wantErr: true},
		{name: "bad unit", settings: map[string]any{"window": map[string]any{"unit": "fortnight", "max": 100}}, wantErr: true},
	}
	p := New(nil, nil, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPlugin_Execute_SkipsWhenNoProvider(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, &infracontext.RequestContext{}, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.Headers)
}

func TestPlugin_PreRequest_AllowsAndReports(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}
	req := &infracontext.RequestContext{Provider: "openai", IP: "1.1.1.1"}

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"100"}, res.Headers["X-Ratelimit-Limit-Tokens"])
	assert.Equal(t, []string{"100"}, res.Headers["X-Ratelimit-Remaining-Tokens"])
}

func TestPlugin_PostResponse_RecordsTokensAndPreRequestRejects(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", IP: "1.1.1.1"}

	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	// Now the next PreRequest must reject (15 consumed >= 10 limit).
	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
}

func TestPlugin_PreRequest_ObserveDoesNotReject(t *testing.T) {
	p := newTestPlugin(t)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())

	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", IP: "2.2.2.2"}

	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}
	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	in := input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{})
	in.Mode = policy.ModeObserve
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "observe must not reject an over-budget request")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
}

func TestPlugin_PostResponse_StreamingUsesObservedUsage(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}
	req := &infracontext.RequestContext{
		Provider: "openai",
		Metadata: map[string]interface{}{adapter.MetadataUsageKey: &adapter.CanonicalUsage{TotalTokens: 42}},
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Streaming: true}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"58"}, res.Headers["X-Ratelimit-Remaining-Tokens"], "the streamed usage must be charged")
}

func TestPlugin_PostResponse_NoTokensNoRecord(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 100}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{}`)}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
	require.NoError(t, err)
	assert.Equal(t, []string{"100"}, res.Headers["X-Ratelimit-Remaining-Tokens"], "a response without usage must charge nothing")
}

func scopedInput(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext, scope appplugins.RuntimeScope) appplugins.ExecInput {
	in := input(stage, settings, req, resp)
	in.Scope = scope
	return in
}

// A non-global policy must give each consumer an independent token budget even
// when they share the same policy (same Config.ID).
func TestPlugin_ConsumerScopeIsolatesBudgets(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	c1 := appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}
	c2 := appplugins.RuntimeScope{ConsumerID: "c-2", GatewayID: "gw-1"}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, req, resp, c1))
	require.NoError(t, err)

	// c-1 is over budget now.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, c1))
	require.Error(t, err)

	// c-2 shares the policy but keeps its own budget.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, c2))
	require.NoError(t, err, "a sibling consumer must not inherit another consumer's token usage")
}

// A global policy shares one token counter across consumers of the gateway.
func TestPlugin_GlobalScopeSharesBudget(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	global := appplugins.RuntimeScope{GatewayID: "gw-1", Global: true}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, req, resp, global))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, global))
	require.Error(t, err, "the shared global budget must gate the next request from any consumer")
}

// With a group_by_header configured, the token budget is sub-partitioned by
// header value within the policy scope: distinct values get independent budgets.
func TestPlugin_GroupByHeaderIsolatesBudgets(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"window":          map[string]any{"unit": "minute", "max": 10},
		"group_by_header": "X-User-Id",
	}
	scope := appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}
	body := []byte(`{"id":"x","model":"gpt","choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)

	reqU1 := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Headers: map[string][]string{"X-User-Id": {"user-1"}}}
	reqU2 := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Headers: map[string][]string{"X-User-Id": {"user-2"}}}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: body}

	// user-1 consumes its whole budget.
	_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, reqU1, resp, scope))
	require.NoError(t, err)

	// user-1 is now over budget.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, reqU1, &infracontext.ResponseContext{}, scope))
	require.Error(t, err)

	// user-2 has an independent budget within the same consumer.
	_, err = p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, reqU2, &infracontext.ResponseContext{}, scope))
	require.NoError(t, err, "a different header value must have an independent token budget")
}

func TestPlugin_ConsumerScopeRequiresConsumerID(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
	req := &infracontext.RequestContext{Provider: "openai"}

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, appplugins.RuntimeScope{GatewayID: "gw-1"}))
	require.Error(t, err)
}

// commandBreakerHook fails any command (plain, or inside a pipeline/script)
// whose name is in targets, letting everything else — including go-redis's
// own internal connection handshake — through untouched. It is how the tests
// below simulate a counter-store outage on exactly one leg: a GET read
// (budgetGate), or the EVALSHA/EVAL a counting script (recordScript) runs as.
type commandBreakerHook struct {
	targets map[string]struct{}
	err     error
}

func (h commandBreakerHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h commandBreakerHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if _, ok := h.targets[cmd.Name()]; ok {
			return h.err
		}
		return next(ctx, cmd)
	}
}
func (h commandBreakerHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, c := range cmds {
			if _, ok := h.targets[c.Name()]; ok {
				return h.err
			}
		}
		return next(ctx, cmds)
	}
}

func breakReads(err error) commandBreakerHook {
	return commandBreakerHook{targets: map[string]struct{}{"get": {}}, err: err}
}

func breakRecords(err error) commandBreakerHook {
	return commandBreakerHook{targets: map[string]struct{}{"evalsha": {}, "eval": {}}, err: err}
}

func newTestPluginWithHook(t *testing.T, hook redis.Hook) *Plugin {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb.AddHook(hook)
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, adapter.NewRegistry(), nil)
}

// assertTokenCounterFailedOpen asserts the common shape every counter-store
// failure test below expects, including item 3 of the RUN-1675 review: the
// provider (known before any of the three call sites ever touches Redis)
// must survive onto the failure extras rather than being lost to a bare
// TokenRateLimiterData{FailureReason, FailureDetail} — see counterUnavailable
// in budget.go.
func assertTokenCounterFailedOpen(t *testing.T, res *appplugins.Result, err error, span *trace.Span, wantDetail string) {
	t.Helper()
	require.NoError(t, err, "a counter-store failure must never reject the request")
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
	require.NotNil(t, span.Plugin)
	assert.Equal(t, "failed_open", span.Plugin.Decision)
	data, ok := span.Plugin.Extras.(TokenRateLimiterData)
	require.True(t, ok, "extras should carry token rate limiter data")
	assert.Equal(t, string(appplugins.FailureCounterUnavailable), data.FailureReason)
	assert.Equal(t, wantDetail, data.FailureDetail)
	assert.Equal(t, "openai", data.Provider, "provider telemetry must survive the failure, not be discarded")
}

// TestPlugin_PreRequest_CounterStoreReadFailureFailsOpen proves RUN-1675 for
// budgetGate's read leg: a counter-store outage never rejects the request,
// in enforce or in observe, unlike a budget actually exceeded.
func TestPlugin_PreRequest_CounterStoreReadFailureFailsOpen(t *testing.T) {
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			p := newTestPluginWithHook(t, breakReads(errors.New("dial tcp: connection refused")))
			settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
			req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}

			rt := trace.New("t", trace.Metadata{})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			in := input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{})
			in.Mode = mode
			in.Event = metrics.NewEventContext(span)

			res, err := p.Execute(context.Background(), in)
			assertTokenCounterFailedOpen(t, res, err, span, "read_counter")
		})
	}
}

// TestPlugin_PostResponse_CounterStoreRecordTokensFailureFailsOpen proves the
// same rule for accrue's record leg (a token-unit budget): a write-back
// failure after the response is already known must not turn into a
// rejection — there is nothing left to reject at that point anyway, but the
// failure still has to be visible on the event, not just in a log line.
func TestPlugin_PostResponse_CounterStoreRecordTokensFailureFailsOpen(t *testing.T) {
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			p := newTestPluginWithHook(t, breakRecords(errors.New("dial tcp: connection refused")))
			settings := map[string]any{"window": map[string]any{"unit": "minute", "max": 10}}
			req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
			resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

			rt := trace.New("t", trace.Metadata{})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			in := input(policy.StagePostResponse, settings, req, resp)
			in.Mode = mode
			in.Event = metrics.NewEventContext(span)

			res, err := p.Execute(context.Background(), in)
			assertTokenCounterFailedOpen(t, res, err, span, "record_tokens")
		})
	}
}

// TestPlugin_PostResponse_CounterStoreRecordCostFailureFailsOpen is the same
// record failure, for a dollar-unit budget's accrueDollars path.
func TestPlugin_PostResponse_CounterStoreRecordCostFailureFailsOpen(t *testing.T) {
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			p := newTestPluginWithHook(t, breakRecords(errors.New("dial tcp: connection refused")))
			settings := map[string]any{
				"unit":          "dollars",
				"pricing_table": "custom",
				"custom_pricing": map[string]any{
					"gpt-4o-mini": map[string]any{"input": 0.001, "output": 0},
				},
				"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
			}
			req := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"gpt-4o-mini"}`)}
			resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

			rt := trace.New("t", trace.Metadata{})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			in := input(policy.StagePostResponse, settings, req, resp)
			in.Mode = mode
			in.Event = metrics.NewEventContext(span)

			res, err := p.Execute(context.Background(), in)
			assertTokenCounterFailedOpen(t, res, err, span, "record_cost")
		})
	}
}
