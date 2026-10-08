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

package regexreplace

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	toolEmail  = "jane.doe@example.com"
	toolMasked = "[MASKED_EMAIL]"
	emailRegex = `[a-z.]+@[a-z.]+\.[a-z]+`
)

func toolMaskSettings(target string) map[string]any {
	return settings(target, maskRule(emailRegex, toolMasked))
}

func jsonAt(t *testing.T, raw []byte, path ...any) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	for _, p := range path {
		switch k := p.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func TestToolArgumentsAreMaskedInResponses(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	t.Run("converse toolUse", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"tooluse_1","name":"send_email","input":{"to":"` + toolEmail + `"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}`)
		event, span := newEvent()
		res, err := p.Execute(context.Background(),
			execInput(policy.StagePreResponse, policy.ModeEnforce, toolMaskSettings(targetResponse), nativeReq("converse", `{"messages":[]}`), respCtx(body, false), event))
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, extras(t, span).Changed)
		out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, res.Body)
		require.Empty(t, cause)
		assert.Equal(t, toolMasked, jsonAt(t, out, "output", "message", "content", 0, "toolUse", "input", "to"))
		assert.NotContains(t, string(out), toolEmail)
	})

	t.Run("anthropic invoke tool_use", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"Sending now."},{"type":"tool_use","id":"toolu_1","name":"send_email","input":{"to":"` + toolEmail + `"}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
		event, _ := newEvent()
		res, err := p.Execute(context.Background(),
			execInput(policy.StagePreResponse, policy.ModeEnforce, toolMaskSettings(targetResponse), nativeReq("invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`), respCtx(body, false), event))
		require.NoError(t, err)
		require.NotNil(t, res)
		out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, res.Body)
		require.Empty(t, cause)
		assert.Equal(t, toolMasked, jsonAt(t, out, "content", 1, "input", "to"))
		assert.Equal(t, "Sending now.", jsonAt(t, out, "content", 0, "text"))
	})

	t.Run("openai tool_calls", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"` + toolEmail + `\"}"}}]},"finish_reason":"tool_calls"}]}`)
		event, _ := newEvent()
		res, err := p.Execute(context.Background(),
			execInput(policy.StagePreResponse, policy.ModeEnforce, toolMaskSettings(targetResponse), reqCtx(openAIProvider, "", openAIRequest("s", "u")), respCtx(body, false), event))
		require.NoError(t, err)
		require.NotNil(t, res)
		args, ok := jsonAt(t, res.Body, "choices", 0, "message", "tool_calls", 0, "function", "arguments").(string)
		require.True(t, ok)
		assert.JSONEq(t, `{"to":"`+toolMasked+`"}`, args)
	})
}

func TestToolArgumentsAreMaskedInRequestHistory(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	t.Run("converse toolUse", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[{"role":"user","content":[{"text":"email jane"}]},{"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"send_email","input":{"to":"` + toolEmail + `"}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"t1","content":[{"text":"sent"}]}}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"send_email","description":"send","inputSchema":{"json":{"type":"object","properties":{"to":{"type":"string"}}}}}}]}}`)
		event, _ := newEvent()
		res, err := p.Execute(context.Background(),
			execInput(policy.StagePreRequest, policy.ModeEnforce, toolMaskSettings(targetRequest), nativeReq("converse", string(body)), nil, event))
		require.NoError(t, err)
		out, cause := adapter.NativeMasker{}.MaskRequestWhy(body, res.RequestBody)
		require.Empty(t, cause)
		assert.Equal(t, toolMasked, jsonAt(t, out, "messages", 1, "content", 0, "toolUse", "input", "to"))
		assert.NotContains(t, string(out), toolEmail)
	})

	t.Run("anthropic invoke tool_use", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"email jane"}]},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"send_email","input":{"to":"` + toolEmail + `"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"sent"}]}],"tools":[{"name":"send_email","description":"send","input_schema":{"type":"object","properties":{"to":{"type":"string"}}}}]}`)
		event, _ := newEvent()
		res, err := p.Execute(context.Background(),
			execInput(policy.StagePreRequest, policy.ModeEnforce, toolMaskSettings(targetRequest), nativeReq("invoke", string(body)), nil, event))
		require.NoError(t, err)
		out, cause := adapter.NativeMasker{}.MaskRequestWhy(body, res.RequestBody)
		require.Empty(t, cause)
		assert.Equal(t, toolMasked, jsonAt(t, out, "messages", 1, "content", 0, "input", "to"))
	})

	t.Run("openai tool_calls", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"email jane"},{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"` + toolEmail + `\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"sent"}]}`)
		event, _ := newEvent()
		res, err := p.Execute(context.Background(),
			execInput(policy.StagePreRequest, policy.ModeEnforce, toolMaskSettings(targetRequest), reqCtx(openAIProvider, "", body), nil, event))
		require.NoError(t, err)
		require.NotEmpty(t, res.RequestBody)
		args, ok := jsonAt(t, res.RequestBody, "messages", 1, "tool_calls", 0, "function", "arguments").(string)
		require.True(t, ok)
		assert.JSONEq(t, `{"to":"`+toolMasked+`"}`, args)
	})
}

func TestApplyRulesToArgumentsKeepsJSONValid(t *testing.T) {
	t.Parallel()
	rules := mustCompile(t, Rule{Pattern: `secret`, Replacement: `"quoted" \ value`})

	out, changed := applyRulesToArguments(rules, `{"note":"a secret","n":1.50,"nested":{"list":["secret",2]}}`)
	require.True(t, changed)
	assert.JSONEq(t, `{"note":"a \"quoted\" \\ value","n":1.50,"nested":{"list":["\"quoted\" \\ value",2]}}`, out)

	structural := mustCompile(t, Rule{Pattern: `"`, Replacement: `'`})
	out, changed = applyRulesToArguments(structural, `{"to":"jane"}`)
	assert.False(t, changed, "a rule may not touch the JSON syntax, only string values")
	assert.Equal(t, `{"to":"jane"}`, out)

	out, changed = applyRulesToArguments(rules, `a secret freeform input`)
	assert.True(t, changed)
	assert.Equal(t, `a "quoted" \ value freeform input`, out)

	_, changed = applyRulesToArguments(rules, `{"to":"nothing"}`)
	assert.False(t, changed)
}

func TestApplyRulesToArgumentsScalarsAndNumbers(t *testing.T) {
	t.Parallel()
	rules := mustCompile(t, Rule{Pattern: `\b\d{16}\b`, Replacement: "[CARD]"})

	tests := []struct {
		name    string
		args    string
		want    string
		changed bool
	}{
		{"number value becomes masked string", `{"card": 4111111111111111}`, `{"card": "[CARD]"}`, true},
		{"freeform scalar takes the rules whole", `4111111111111111`, `[CARD]`, true},
		{"unrelated number untouched", `{"n": 42, "x": 1.50}`, `{"n": 42, "x": 1.50}`, false},
		{"nested arrays", `{"a": [[1, 4111111111111111], {"b": [4111111111111111]}]}`, `{"a": [[1, "[CARD]"], {"b": ["[CARD]"]}]}`, true},
		{"top-level array", `[4111111111111111, "4111111111111111"]`, `["[CARD]", "[CARD]"]`, true},
		{"key is not rewritten", `{"4111111111111111": 1}`, `{"4111111111111111": 1}`, false},
		{"trailing data is freeform", `{"a": 1} 4111111111111111`, `{"a": 1} [CARD]`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, changed := applyRulesToArguments(rules, tt.args)
			assert.Equal(t, tt.changed, changed)
			assert.Equal(t, tt.want, out)
		})
	}
}

// A mask is carried onto a native request by diffing the text before and after,
// which only works when the arguments keep their key order and spacing.
func TestToolArgumentsKeepTheirBytesOnNativeRequests(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	inputs := map[string]string{
		"two keys unsorted":   `{"to": "` + toolEmail + `", "subject": "Hello there"}`,
		"cc after to":         `{"to":"x@y.io","cc":"z","bcc":"` + toolEmail + `"}`,
		"spaced single key":   `{ "to" : "` + toolEmail + `" }`,
		"escapes preserved":   `{"z":"aé\n","to":"` + toolEmail + `","a":1}`,
		"nested out of order": `{"b":{"y":1,"x":"` + toolEmail + `"},"a":[1, 2]}`,
	}
	for name, input := range inputs {
		t.Run("converse "+name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]},{"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"send_email","input":` + input + `}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"t1","content":[{"text":"sent"}]}}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"send_email","description":"send","inputSchema":{"json":{"type":"object"}}}}]}}`)
			event, _ := newEvent()
			res, err := p.Execute(context.Background(),
				execInput(policy.StagePreRequest, policy.ModeEnforce, toolMaskSettings(targetRequest), nativeReq("converse", string(body)), nil, event))
			require.NoError(t, err)
			out, cause := adapter.NativeMasker{}.MaskRequestWhy(body, res.RequestBody)
			require.Empty(t, cause)
			assert.NotContains(t, string(out), toolEmail)
			assert.Contains(t, string(out), toolMasked)
		})
		t.Run("anthropic invoke "+name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"send_email","input":` + input + `}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"sent"}]}],"tools":[{"name":"send_email","description":"send","input_schema":{"type":"object"}}]}`)
			event, _ := newEvent()
			res, err := p.Execute(context.Background(),
				execInput(policy.StagePreRequest, policy.ModeEnforce, toolMaskSettings(targetRequest), nativeReq("invoke", string(body)), nil, event))
			require.NoError(t, err)
			out, cause := adapter.NativeMasker{}.MaskRequestWhy(body, res.RequestBody)
			require.Empty(t, cause)
			assert.NotContains(t, string(out), toolEmail)
			assert.Contains(t, string(out), toolMasked)
		})
		t.Run("converse response "+name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"tooluse_1","name":"send_email","input":` + input + `}}]}},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}`)
			event, _ := newEvent()
			res, err := p.Execute(context.Background(),
				execInput(policy.StagePreResponse, policy.ModeEnforce, toolMaskSettings(targetResponse), nativeReq("converse", `{"messages":[]}`), respCtx(body, false), event))
			require.NoError(t, err)
			out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, res.Body)
			require.Empty(t, cause)
			assert.NotContains(t, string(out), toolEmail)
			assert.Contains(t, string(out), toolMasked)
		})
		t.Run("anthropic response "+name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"tool_use","id":"toolu_1","name":"send_email","input":` + input + `}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
			event, _ := newEvent()
			res, err := p.Execute(context.Background(),
				execInput(policy.StagePreResponse, policy.ModeEnforce, toolMaskSettings(targetResponse), nativeReq("invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`), respCtx(body, false), event))
			require.NoError(t, err)
			out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, res.Body)
			require.Empty(t, cause)
			assert.NotContains(t, string(out), toolEmail)
			assert.Contains(t, string(out), toolMasked)
		})
	}
}

func TestApplyRulesToArgumentsChangesOnlyTheMaskedSpan(t *testing.T) {
	t.Parallel()
	rules := mustCompile(t, Rule{Pattern: emailRegex, Replacement: toolMasked})
	in := "{ \"z\" : \"caf\\u00e9\\n\" ,\"to\":  \"" + toolEmail + "\", \"a\":[1 ,2 ]}"
	out, changed := applyRulesToArguments(rules, in)
	require.True(t, changed)
	assert.Equal(t, "{ \"z\" : \"caf\\u00e9\\n\" ,\"to\":  \""+toolMasked+"\", \"a\":[1 ,2 ]}", out)
}
