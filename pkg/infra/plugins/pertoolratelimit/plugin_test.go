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
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Stages(t *testing.T) {
	p := New(nil, nil)
	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, "per_tool_rate_limiter", p.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreResponse}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreResponse}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce}, p.SupportedModes())
}

func TestPlugin_New_Defaults(t *testing.T) {
	p := New(nil, nil)
	require.NotNil(t, p.now)
	assert.Nil(t, p.redis)
	assert.Nil(t, p.registry)
}

func TestPlugin_WithClock(t *testing.T) {
	fixed := time.Unix(1000, 0)
	p := New(nil, nil, WithClock(func() time.Time { return fixed }))
	assert.Equal(t, fixed, p.now())
}

func TestPlugin_Execute_Noop(t *testing.T) {
	p := New(nil, nil)
	res, err := p.Execute(context.Background(), appplugins.ExecInput{Stage: policy.StagePreResponse})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPlugin_RateLimitTemplate(t *testing.T) {
	msg := fmt.Sprintf(rateLimitTemplate, "send_email", "call_1")
	assert.Contains(t, msg, "send_email")
	assert.Contains(t, msg, "call_1")
}

func run695Settings() map[string]any {
	return map[string]any{
		"scope": "consumer",
		"rules": []any{
			map[string]any{
				"tool": "execute_code*",
				"windows": []any{
					map[string]any{"duration": "1h", "max": 50},
				},
				"behavior": "inject_error_result",
			},
		},
		"behavior_default": "reject_response",
	}
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid RUN-695 config",
			settings: run695Settings(),
		},
		{
			name: "rule without behavior uses default",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "*",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
		},
		{
			name: "empty rules",
			settings: map[string]any{
				"behavior_default": "reject_response",
				"rules":            []any{},
			},
			wantErr: true,
		},
		{
			name: "missing rules",
			settings: map[string]any{
				"behavior_default": "reject_response",
			},
			wantErr: true,
		},
		{
			name: "empty tool",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "bad glob pattern",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "[",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no windows",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unparseable duration",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "abc", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "zero duration",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "0s", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "fractional duration",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1500ms", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "max not positive",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1m", "max": 0}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "bad behavior",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":     "send_email",
						"windows":  []any{map[string]any{"duration": "1m", "max": 5}},
						"behavior": "explode",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "strip behavior rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":     "send_email",
						"windows":  []any{map[string]any{"duration": "1m", "max": 5}},
						"behavior": "strip_tool_from_request",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "strip behavior_default rejected",
			settings: map[string]any{
				"behavior_default": "strip_tool_from_request",
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "bad scope",
			settings: map[string]any{
				"scope": "tenant",
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
	}

	p := New(nil, nil)
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

func TestPlugin_AppearsInCatalog(t *testing.T) {
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(New(nil, nil)))

	catalog := appplugins.NewCatalogService(reg).Catalog()

	var entry appplugins.CatalogEntry
	found := false
	for _, group := range catalog.Groups {
		for _, item := range group.Items {
			if item.Slug == PluginName {
				entry = item
				found = true
			}
		}
	}
	require.Truef(t, found, "slug %q missing from catalog", PluginName)
	assert.Equal(t, []policy.Stage{policy.StagePreResponse}, entry.SupportedStages)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce}, entry.SupportedModes)
	assert.NotEmpty(t, entry.SettingsSchema.Fields)
}

type tcSpec struct {
	id   string
	name string
}

func newPluginRedis(t *testing.T, opts ...Option) (*Plugin, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, adapter.NewRegistry(), opts...), rdb
}

func openAIToolBody(t *testing.T, calls ...tcSpec) []byte {
	t.Helper()
	toolCalls := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		toolCalls = append(toolCalls, map[string]any{
			"id":       c.id,
			"type":     "function",
			"function": map[string]any{"name": c.name, "arguments": "{}"},
		})
	}
	body := map[string]any{
		"id":    "resp_1",
		"model": "gpt",
		"choices": []any{
			map[string]any{
				"message":       map[string]any{"role": "assistant", "content": "", "tool_calls": toolCalls},
				"finish_reason": "tool_calls",
			},
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func openAIReq() *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai"}
}

func anthropicToolBody(t *testing.T, calls ...tcSpec) []byte {
	t.Helper()
	content := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		content = append(content, map[string]any{
			"type":  "tool_use",
			"id":    c.id,
			"name":  c.name,
			"input": map[string]any{},
		})
	}
	body := map[string]any{
		"id":          "msg_1",
		"type":        "message",
		"role":        "assistant",
		"model":       "claude",
		"content":     content,
		"stop_reason": "tool_use",
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func anthropicReq() *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: "anthropic", SourceFormat: "anthropic"}
}

func execInput(settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    policy.StagePreResponse,
		Config:   policy.PluginConfig{ID: "pt-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:    appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request:  req,
		Response: resp,
	}
}

func rejectSettings(tool, duration string, max int) map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"tool":     tool,
				"windows":  []any{map[string]any{"duration": duration, "max": max}},
				"behavior": "reject_response",
			},
		},
	}
}

func TestPlugin_Execute_NoopPaths(t *testing.T) {
	settings := rejectSettings("send_email", "1m", 5)

	tests := []struct {
		name string
		req  *infracontext.RequestContext
		resp *infracontext.ResponseContext
	}{
		{name: "nil request", req: nil, resp: &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}},
		{name: "nil response", req: openAIReq(), resp: nil},
		{name: "streaming", req: openAIReq(), resp: &infracontext.ResponseContext{Streaming: true}},
		{name: "empty body", req: openAIReq(), resp: &infracontext.ResponseContext{Body: nil}},
		{name: "unresolved format", req: &infracontext.RequestContext{}, resp: &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}},
		{name: "undecodable body", req: openAIReq(), resp: &infracontext.ResponseContext{Body: []byte("{not-json")}},
		{name: "no tool calls", req: openAIReq(), resp: &infracontext.ResponseContext{Body: []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)}},
		{name: "unmatched tool", req: openAIReq(), resp: &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "lookup"})}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newPluginRedis(t)
			res, err := p.Execute(context.Background(), execInput(settings, tt.req, tt.resp))
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, http.StatusOK, res.StatusCode)
			assert.False(t, res.StopUpstream)
			assert.Nil(t, res.Body)
		})
	}
}

func TestPlugin_Execute_UnderLimitRecords(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := rejectSettings("send_email", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}

	res, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	val, err := rdb.Get(context.Background(), "pertoolrl:pt-1:consumer:c-1:send_email:w0").Result()
	require.NoError(t, err)
	assert.Equal(t, "1", val)

	ttl, err := rdb.TTL(context.Background(), "pertoolrl:pt-1:consumer:c-1:send_email:w0").Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestPlugin_Execute_CountsEachToolCallOncePerResponse(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := rejectSettings("send_email", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"}, tcSpec{"call_2", "send_email"})}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)

	val, err := rdb.Get(context.Background(), "pertoolrl:pt-1:consumer:c-1:send_email:w0").Result()
	require.NoError(t, err)
	assert.Equal(t, "2", val)
}

func TestPlugin_Execute_ExceedAcrossTwoWindows(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool": "send_email",
				"windows": []any{
					map[string]any{"duration": "1m", "max": 5},
					map[string]any{"duration": "1h", "max": 50},
				},
				"behavior": "reject_response",
			},
		},
	}
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}

	for i := 0; i < 5; i++ {
		res, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)

	hour, err := rdb.Get(context.Background(), "pertoolrl:pt-1:consumer:c-1:send_email:w1").Result()
	require.NoError(t, err)
	assert.Equal(t, "6", hour)
}

func TestPlugin_Execute_GlobMatchAndDefaultBehavior(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool":    "execute_code*",
				"windows": []any{map[string]any{"duration": "1m", "max": 1}},
			},
		},
		"behavior_default": "reject_response",
	}
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "execute_code_py"})}

	res, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	_, err = p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
}

func TestPlugin_Execute_FirstMatchingRuleWins(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool":     "send_*",
				"windows":  []any{map[string]any{"duration": "1m", "max": 1}},
				"behavior": "reject_response",
			},
			map[string]any{
				"tool":     "*",
				"windows":  []any{map[string]any{"duration": "1m", "max": 100}},
				"behavior": "inject_error_result",
			},
		},
	}
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
}

func TestPlugin_Execute_ScopeIsolation(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := rejectSettings("send_email", "1m", 1)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}

	consumer := execInput(settings, openAIReq(), resp)
	consumer.Scope = appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}

	global := execInput(settings, openAIReq(), resp)
	global.Scope = appplugins.RuntimeScope{GatewayID: "gw-1", Global: true}

	_, err := p.Execute(context.Background(), consumer)
	require.NoError(t, err)
	_, err = p.Execute(context.Background(), consumer)
	_, ok := appplugins.AsPluginError(err)
	require.True(t, ok)

	res, err := p.Execute(context.Background(), global)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	consumerVal, err := rdb.Get(context.Background(), "pertoolrl:pt-1:consumer:c-1:send_email:w0").Result()
	require.NoError(t, err)
	assert.Equal(t, "2", consumerVal)

	globalVal, err := rdb.Get(context.Background(), "pertoolrl:pt-1:global:gw-1:send_email:w0").Result()
	require.NoError(t, err)
	assert.Equal(t, "1", globalVal)
}

func TestPlugin_Execute_ConcurrentIncrementsAtomic(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := rejectSettings("send_email", "1m", 100000)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	val, err := rdb.Get(context.Background(), "pertoolrl:pt-1:consumer:c-1:send_email:w0").Result()
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", n), val)
}

func TestPlugin_Execute_RejectHeaders(t *testing.T) {
	fixed := time.Unix(1000, 0)
	p, _ := newPluginRedis(t, WithClock(func() time.Time { return fixed }))
	settings := rejectSettings("send_email", "1m", 1)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "send_email"})}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
	assert.Equal(t, `tool "send_email" rate limit exceeded`, pe.Message)
	assert.Equal(t, []string{"1"}, pe.Headers["X-RateLimit-consumer-Limit"])
	assert.Equal(t, []string{"0"}, pe.Headers["X-RateLimit-consumer-Remaining"])
	assert.Equal(t, []string{fmt.Sprintf("%d", fixed.Add(time.Minute).Unix())}, pe.Headers["X-RateLimit-consumer-Reset"])
	assert.Equal(t, []string{"send_email"}, pe.Headers["X-RateLimit-Tool"])
	assert.Equal(t, []string{"60"}, pe.Headers["Retry-After"])
}

func injectSettings(tool, duration string, max int) map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{
				"tool":     tool,
				"windows":  []any{map[string]any{"duration": duration, "max": max}},
				"behavior": "inject_error_result",
			},
		},
	}
}

func TestPlugin_Execute_InjectOpenAIRoundTrip(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := injectSettings("execute_code*", "1m", 1)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t, tcSpec{"call_1", "execute_code_py"})}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.StopUpstream)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	require.NotNil(t, res.Body)

	decoded, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatOpenAI)
	require.NoError(t, err)
	assert.Empty(t, decoded.ToolCalls)
	assert.Contains(t, decoded.Content, "execute_code_py")
	assert.Contains(t, decoded.Content, "call_1")
	assert.Equal(t, "stop", decoded.FinishReason)
}

func TestPlugin_Execute_InjectAnthropicRoundTrip(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := injectSettings("execute_code*", "1m", 1)
	resp := &infracontext.ResponseContext{Body: anthropicToolBody(t, tcSpec{"toolu_1", "execute_code_py"})}

	_, err := p.Execute(context.Background(), execInput(settings, anthropicReq(), resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), execInput(settings, anthropicReq(), resp))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.StopUpstream)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	require.NotNil(t, res.Body)

	decoded, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatAnthropic)
	require.NoError(t, err)
	assert.Empty(t, decoded.ToolCalls)
	assert.Contains(t, decoded.Content, "execute_code_py")
	assert.Contains(t, decoded.Content, "toolu_1")
	assert.Equal(t, "stop", decoded.FinishReason)
}

func TestPlugin_Execute_InjectKeepsOtherToolCalls(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := injectSettings("execute_code*", "1m", 1)
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t,
		tcSpec{"call_1", "execute_code_py"},
		tcSpec{"call_2", "lookup"},
	)}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)

	res, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.StopUpstream)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	decoded, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, decoded.ToolCalls, 1)
	assert.Equal(t, "lookup", decoded.ToolCalls[0].Name)
	assert.Contains(t, decoded.Content, "execute_code_py")
	assert.Equal(t, "tool_calls", decoded.FinishReason)
}

func TestPlugin_Execute_RejectWinsOverInject(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool":     "send_email",
				"windows":  []any{map[string]any{"duration": "1m", "max": 1}},
				"behavior": "reject_response",
			},
			map[string]any{
				"tool":     "execute_code*",
				"windows":  []any{map[string]any{"duration": "1m", "max": 1}},
				"behavior": "inject_error_result",
			},
		},
	}
	resp := &infracontext.ResponseContext{Body: openAIToolBody(t,
		tcSpec{"call_1", "execute_code_py"},
		tcSpec{"call_2", "send_email"},
	)}

	_, err := p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), execInput(settings, openAIReq(), resp))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
	assert.Equal(t, `tool "send_email" rate limit exceeded`, pe.Message)
}
