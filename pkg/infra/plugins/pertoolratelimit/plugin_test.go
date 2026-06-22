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

func allStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse, policy.StagePostResponse}
}

func TestPlugin_Stages(t *testing.T) {
	p := New(nil, nil)
	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, allStages(), p.MandatoryStages())
	assert.Equal(t, allStages(), p.SupportedStages())
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

func TestPlugin_Execute_NilDeps(t *testing.T) {
	p := New(nil, nil)
	res, err := p.Execute(context.Background(), appplugins.ExecInput{Stage: policy.StagePostResponse})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPlugin_RateLimitTemplate(t *testing.T) {
	msg := fmt.Sprintf(rateLimitTemplate, "send_email", "call_1")
	assert.Contains(t, msg, "send_email")
	assert.Contains(t, msg, "call_1")
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name: "valid reject",
			settings: map[string]any{
				"rules": []any{map[string]any{
					"tool": "execute_code*", "windows": []any{map[string]any{"duration": "1h", "max": 50}},
					"behavior": "reject_response",
				}},
			},
		},
		{
			name: "valid inject",
			settings: map[string]any{
				"rules": []any{map[string]any{
					"tool": "execute_code*", "windows": []any{map[string]any{"duration": "1h", "max": 50}},
					"behavior": "inject_error_result",
				}},
			},
		},
		{
			name: "valid strip",
			settings: map[string]any{
				"rules": []any{map[string]any{
					"tool": "send_email", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
					"behavior": "strip_tool_from_request",
				}},
			},
		},
		{
			name: "valid strip default",
			settings: map[string]any{
				"behavior_default": "strip_tool_from_request",
				"rules": []any{map[string]any{
					"tool": "send_email", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
				}},
			},
		},
		{
			name: "rule without behavior uses default",
			settings: map[string]any{
				"rules": []any{map[string]any{
					"tool": "*", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
				}},
			},
		},
		{
			name:     "empty rules",
			settings: map[string]any{"behavior_default": "reject_response", "rules": []any{}},
			wantErr:  true,
		},
		{
			name:     "missing rules",
			settings: map[string]any{"behavior_default": "reject_response"},
			wantErr:  true,
		},
		{
			name: "empty tool",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
			}}},
			wantErr: true,
		},
		{
			name: "bad glob",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "[", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
			}}},
			wantErr: true,
		},
		{
			name: "no windows",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{},
			}}},
			wantErr: true,
		},
		{
			name: "unparseable duration",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{map[string]any{"duration": "abc", "max": 5}},
			}}},
			wantErr: true,
		},
		{
			name: "zero duration",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{map[string]any{"duration": "0s", "max": 5}},
			}}},
			wantErr: true,
		},
		{
			name: "fractional duration",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{map[string]any{"duration": "1500ms", "max": 5}},
			}}},
			wantErr: true,
		},
		{
			name: "max not positive",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{map[string]any{"duration": "1m", "max": 0}},
			}}},
			wantErr: true,
		},
		{
			name: "bad behavior",
			settings: map[string]any{"rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
				"behavior": "explode",
			}}},
			wantErr: true,
		},
		{
			name: "bad scope",
			settings: map[string]any{"scope": "tenant", "rules": []any{map[string]any{
				"tool": "send_email", "windows": []any{map[string]any{"duration": "1m", "max": 5}},
			}}},
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
	assert.Equal(t, allStages(), entry.SupportedStages)
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

func openAIRespBody(t *testing.T, calls ...tcSpec) []byte {
	t.Helper()
	toolCalls := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		toolCalls = append(toolCalls, map[string]any{
			"id": c.id, "type": "function",
			"function": map[string]any{"name": c.name, "arguments": "{}"},
		})
	}
	body := map[string]any{
		"id": "resp_1", "model": "gpt",
		"choices": []any{map[string]any{
			"message":       map[string]any{"role": "assistant", "content": "", "tool_calls": toolCalls},
			"finish_reason": "tool_calls",
		}},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func openAIStreamBody(t *testing.T, calls ...tcSpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	for i, c := range calls {
		chunk := map[string]any{
			"id": "x", "object": "chat.completion.chunk",
			"choices": []any{map[string]any{
				"index": 0,
				"delta": map[string]any{"tool_calls": []any{map[string]any{
					"index": i, "id": c.id, "type": "function",
					"function": map[string]any{"name": c.name, "arguments": ""},
				}}},
			}},
		}
		b, err := json.Marshal(chunk)
		require.NoError(t, err)
		buf.WriteString("data: ")
		buf.Write(b)
		buf.WriteString("\n\n")
	}
	buf.WriteString("data: [DONE]\n")
	return buf.Bytes()
}

func openAIReqBody(t *testing.T, tools ...string) []byte {
	t.Helper()
	specs := make([]map[string]any, 0, len(tools))
	for _, name := range tools {
		specs = append(specs, map[string]any{
			"type":     "function",
			"function": map[string]any{"name": name, "parameters": map[string]any{"type": "object"}},
		})
	}
	body := map[string]any{
		"model":    "gpt",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"tools":    specs,
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func anthropicRespBody(t *testing.T, calls ...tcSpec) []byte {
	t.Helper()
	content := make([]map[string]any, 0, len(calls))
	for _, c := range calls {
		content = append(content, map[string]any{
			"type": "tool_use", "id": c.id, "name": c.name, "input": map[string]any{},
		})
	}
	body := map[string]any{
		"id": "msg_1", "type": "message", "role": "assistant", "model": "claude",
		"content": content, "stop_reason": "tool_use",
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func openAIReq(body []byte) *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: body}
}

func anthropicReq(body []byte) *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: "anthropic", SourceFormat: "anthropic", Body: body}
}

func input(stage policy.Stage, settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Config:   policy.PluginConfig{ID: "pt-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:    appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"},
		Request:  req,
		Response: resp,
	}
}

func ruleSettings(tool, behavior, duration string, max int) map[string]any {
	return map[string]any{
		"rules": []any{map[string]any{
			"tool": tool, "behavior": behavior,
			"windows": []any{map[string]any{"duration": duration, "max": max}},
		}},
	}
}

func consumerKey(tool string, win int) string {
	return counterKey("pt-1", "consumer", "c-1", tool, win)
}

func seed(t *testing.T, rdb *redis.Client, key string, val int) {
	t.Helper()
	require.NoError(t, rdb.Set(context.Background(), key, val, time.Minute).Err())
}

func TestPlugin_PostResponse_CountsNonStreaming(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "send_email"})}

	res, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	val, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", val)

	ttl, err := rdb.TTL(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestPlugin_PostResponse_CountsEachToolCall(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "send_email"}, tcSpec{"call_2", "send_email"})}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)

	val, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, "2", val)
}

func TestPlugin_PostResponse_CountsStreaming(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	resp := &infracontext.ResponseContext{
		Streaming: true,
		Body:      openAIStreamBody(t, tcSpec{"call_1", "send_email"}, tcSpec{"call_2", "send_email"}),
	}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)

	val, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, "2", val)
}

func TestPlugin_PostResponse_TwoWindows(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := map[string]any{
		"rules": []any{map[string]any{
			"tool":     "send_email",
			"behavior": "reject_response",
			"windows": []any{
				map[string]any{"duration": "1m", "max": 5},
				map[string]any{"duration": "1h", "max": 50},
			},
		}},
	}
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "send_email"})}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)

	w0, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", w0)
	w1, err := rdb.Get(context.Background(), consumerKey("send_email", 1)).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", w1)
}

func TestPlugin_PostResponse_UnmatchedToolNoCount(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "lookup"})}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)

	_, err = rdb.Get(context.Background(), consumerKey("lookup", 0)).Result()
	assert.ErrorIs(t, err, redis.Nil)
}

func TestPlugin_PostResponse_ScopeIsolation(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "send_email"})}

	consumer := input(policy.StagePostResponse, settings, openAIReq(nil), resp)
	global := input(policy.StagePostResponse, settings, openAIReq(nil), resp)
	global.Scope = appplugins.RuntimeScope{GatewayID: "gw-1", Global: true}

	_, err := p.Execute(context.Background(), consumer)
	require.NoError(t, err)
	_, err = p.Execute(context.Background(), global)
	require.NoError(t, err)

	cVal, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", cVal)
	gVal, err := rdb.Get(context.Background(), counterKey("pt-1", "global", "gw-1", "send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, "1", gVal)
}

func TestPlugin_PostResponse_ConcurrentAtomic(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 100000)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "send_email"})}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	val, err := rdb.Get(context.Background(), consumerKey("send_email", 0)).Result()
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", n), val)
}

func TestPlugin_PreRequest_RejectWhenOverBudget(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email")), nil))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
	assert.Equal(t, `tool "send_email" rate limit exceeded`, pe.Message)
}

func TestPlugin_PreRequest_NoRejectUnderBudget(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 4)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email")), nil))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody)
}

func TestPlugin_PreRequest_NoRejectWhenToolNotDeclared(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "lookup")), nil))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPlugin_PreRequest_RejectHeaders(t *testing.T) {
	fixed := time.Unix(1000, 0)
	p, rdb := newPluginRedis(t, WithClock(func() time.Time { return fixed }))
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 7)

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email")), nil))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, []string{"5"}, pe.Headers["X-RateLimit-consumer-Limit"])
	assert.Equal(t, []string{"0"}, pe.Headers["X-RateLimit-consumer-Remaining"])
	assert.Equal(t, []string{fmt.Sprintf("%d", fixed.Add(time.Minute).Unix())}, pe.Headers["X-RateLimit-consumer-Reset"])
	assert.Equal(t, []string{"send_email"}, pe.Headers["X-RateLimit-Tool"])
	assert.Equal(t, []string{"60"}, pe.Headers["Retry-After"])
}

func TestPlugin_PreRequest_StripRemovesOverBudgetTool(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "strip_tool_from_request", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email", "lookup")), nil))
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)

	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, decoded.Tools, 1)
	assert.Equal(t, "lookup", decoded.Tools[0].Name)
}

func TestPlugin_PreRequest_StripPreservesNonCanonicalFields(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "strip_tool_from_request", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	raw := []byte(`{"model":"gpt","messages":[{"role":"user","content":"hi"}],` +
		`"temperature":0.7,"frequency_penalty":0.5,"seed":42,"top_logprobs":3,` +
		`"tools":[` +
		`{"type":"function","function":{"name":"send_email","parameters":{"type":"object"}}},` +
		`{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}`)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(raw), nil))
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)

	var out map[string]any
	require.NoError(t, json.Unmarshal(res.RequestBody, &out))
	assert.EqualValues(t, 0.7, out["temperature"])
	assert.EqualValues(t, 0.5, out["frequency_penalty"])
	assert.EqualValues(t, 42, out["seed"])
	assert.EqualValues(t, 3, out["top_logprobs"])

	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, decoded.Tools, 1)
	assert.Equal(t, "lookup", decoded.Tools[0].Name)
}

func TestPlugin_PreRequest_StripAllToolsRemovesToolsField(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "strip_tool_from_request", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email")), nil))
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)

	var out map[string]any
	require.NoError(t, json.Unmarshal(res.RequestBody, &out))
	_, hasTools := out["tools"]
	assert.False(t, hasTools, "tools field must be dropped when empty")
}

func TestPlugin_PreRequest_StripUnderBudgetNoChange(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "strip_tool_from_request", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 4)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email", "lookup")), nil))
	require.NoError(t, err)
	assert.Nil(t, res.RequestBody)
}

func TestPlugin_PreResponse_InjectWhenOverBudget(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("execute_code*", "inject_error_result", "1m", 1)
	seed(t, rdb, consumerKey("execute_code_py", 0), 1)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "execute_code_py"})}

	res, err := p.Execute(context.Background(), input(policy.StagePreResponse, settings, openAIReq(nil), resp))
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

func TestPlugin_PreResponse_InjectAnthropic(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("execute_code*", "inject_error_result", "1m", 1)
	seed(t, rdb, consumerKey("execute_code_py", 0), 1)
	resp := &infracontext.ResponseContext{Body: anthropicRespBody(t, tcSpec{"toolu_1", "execute_code_py"})}

	res, err := p.Execute(context.Background(), input(policy.StagePreResponse, settings, anthropicReq(nil), resp))
	require.NoError(t, err)
	require.NotNil(t, res.Body)

	decoded, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatAnthropic)
	require.NoError(t, err)
	assert.Empty(t, decoded.ToolCalls)
	assert.Contains(t, decoded.Content, "execute_code_py")
}

func TestPlugin_PreResponse_InjectKeepsOtherToolCalls(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("execute_code*", "inject_error_result", "1m", 1)
	seed(t, rdb, consumerKey("execute_code_py", 0), 1)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t,
		tcSpec{"call_1", "execute_code_py"},
		tcSpec{"call_2", "lookup"},
	)}

	res, err := p.Execute(context.Background(), input(policy.StagePreResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)
	require.NotNil(t, res.Body)

	decoded, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, decoded.ToolCalls, 1)
	assert.Equal(t, "lookup", decoded.ToolCalls[0].Name)
	assert.Equal(t, "tool_calls", decoded.FinishReason)
}

func TestPlugin_PreResponse_NoInjectUnderBudget(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("execute_code*", "inject_error_result", "1m", 5)
	seed(t, rdb, consumerKey("execute_code_py", 0), 4)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "execute_code_py"})}

	res, err := p.Execute(context.Background(), input(policy.StagePreResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.False(t, res.StopUpstream)
	assert.Nil(t, res.Body)
}

func openAIStreamReqBody(t *testing.T, tools ...string) []byte {
	t.Helper()
	body := map[string]any{
		"model":    "gpt",
		"messages": []any{map[string]any{"role": "user", "content": "hi"}},
		"stream":   true,
	}
	specs := make([]map[string]any, 0, len(tools))
	for _, name := range tools {
		specs = append(specs, map[string]any{
			"type":     "function",
			"function": map[string]any{"name": name, "parameters": map[string]any{"type": "object"}},
		})
	}
	body["tools"] = specs
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

func TestPlugin_PreRequest_InjectStreamingDegradesToStrip(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "inject_error_result", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIStreamReqBody(t, "send_email", "lookup")), nil))
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody, "streaming inject must strip the tool at pre_request")

	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, decoded.Tools, 1)
	assert.Equal(t, "lookup", decoded.Tools[0].Name)
}

func TestPlugin_PreRequest_InjectNonStreamingNoStrip(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "inject_error_result", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 5)

	res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email")), nil))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody, "non-streaming inject is handled at pre_response, not pre_request")
}

func TestPlugin_PostResponse_EmptyToolNameNotCounted(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("*", "reject_response", "1m", 5)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", ""})}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)

	_, err = rdb.Get(context.Background(), consumerKey("", 0)).Result()
	assert.ErrorIs(t, err, redis.Nil)
}

func TestMatchToolPattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"get_weather", "get_weather", true},
		{"get_*", "get_weather", true},
		{"execute_code*", "execute_code_py", true},
		{"*", "srv/get_weather", true},
		{"srv/get_*", "srv/get_weather", true},
		{"*/get_weather", "srv/get_weather", true},
		{"get_*", "srv/get_weather", false},
		{"send_email", "send_sms", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"|"+tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchToolPattern(tt.pattern, tt.name))
		})
	}
}

func TestPlugin_PreResponse_StreamingNoop(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("execute_code*", "inject_error_result", "1m", 1)
	seed(t, rdb, consumerKey("execute_code_py", 0), 1)
	resp := &infracontext.ResponseContext{Streaming: true, Body: openAIStreamBody(t, tcSpec{"call_1", "execute_code_py"})}

	res, err := p.Execute(context.Background(), input(policy.StagePreResponse, settings, openAIReq(nil), resp))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.False(t, res.StopUpstream)
}

func TestPlugin_FullCycle_CountThenReject(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 2)
	resp := &infracontext.ResponseContext{Body: openAIRespBody(t, tcSpec{"call_1", "send_email"})}
	reqWithTools := func() *infracontext.RequestContext { return openAIReq(openAIReqBody(t, "send_email")) }

	for i := 0; i < 2; i++ {
		res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqWithTools(), nil))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		_, err = p.Execute(context.Background(), input(policy.StagePostResponse, settings, openAIReq(nil), resp))
		require.NoError(t, err)
	}

	_, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqWithTools(), nil))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
}

func TestPlugin_PreRequest_NoopPaths(t *testing.T) {
	settings := ruleSettings("send_email", "reject_response", "1m", 1)
	tests := []struct {
		name string
		req  *infracontext.RequestContext
	}{
		{name: "nil request", req: nil},
		{name: "empty body", req: openAIReq(nil)},
		{name: "no tools declared", req: openAIReq(openAIReqBody(t))},
		{name: "undecodable body", req: openAIReq([]byte("{not-json"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, rdb := newPluginRedis(t)
			seed(t, rdb, consumerKey("send_email", 0), 5)
			res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, tt.req, nil))
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}
