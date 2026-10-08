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

package trustguard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	toolResponseEmail = "jane.doe@example.com"
	toolResponseMask  = "[MASKED_EMAIL]"
)

func maskToolEmail(s string) string {
	return strings.ReplaceAll(s, toolResponseEmail, toolResponseMask)
}

func nativeToolRequest(op, body string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Provider:      "bedrock",
		SourceFormat:  "bedrock_native",
		GatewayID:     "gw-test",
		Body:          []byte(body),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: bedrocknative.Op(op), ModelID: "m"},
	}
}

func toolResponseValue(t *testing.T, raw []byte, path ...any) any {
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

func executeToolResponse(t *testing.T, req *infracontext.RequestContext, body []byte) ([]byte, bool) {
	t.Helper()
	f := &fakeGuard{echoMask: maskToolEmail}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, settings(""), req, &infracontext.ResponseContext{StatusCode: 200, Body: body}, event)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	attrs := span.PluginAttrsCopy()
	extras, ok := attrs.Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionTransformed, extras.Decision)
	assert.False(t, extras.FailedOpen)
	assert.False(t, extras.Degraded, "a transform that was written back is not recorded as degraded")
	return res.Body, res.StopUpstream
}

func TestResponseToolCallArgumentsAreMasked(t *testing.T) {
	t.Parallel()

	t.Run("native converse toolUse only", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"tooluse_1","name":"send_email","input":{"to":"` + toolResponseEmail + `"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}`)
		got, stop := executeToolResponse(t, nativeToolRequest("converse", `{"messages":[{"role":"user","content":[{"text":"email jane"}]}]}`), body)
		require.True(t, stop)
		out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, got)
		require.Empty(t, cause, "the forwarder blocks or fails open on any cause")
		assert.Equal(t, toolResponseMask, toolResponseValue(t, out, "output", "message", "content", 0, "toolUse", "input", "to"))
		assert.NotContains(t, string(out), toolResponseEmail)
	})

	t.Run("native converse text and toolUse", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"Writing to ` + toolResponseEmail + `."},{"toolUse":{"toolUseId":"tooluse_1","name":"send_email","input":{"to":"` + toolResponseEmail + `"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}`)
		got, _ := executeToolResponse(t, nativeToolRequest("converse", `{"messages":[{"role":"user","content":[{"text":"email jane"}]}]}`), body)
		out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, got)
		require.Empty(t, cause)
		assert.Equal(t, "Writing to "+toolResponseMask+".", toolResponseValue(t, out, "output", "message", "content", 0, "text"))
		assert.Equal(t, toolResponseMask, toolResponseValue(t, out, "output", "message", "content", 1, "toolUse", "input", "to"))
		assert.NotContains(t, string(out), toolResponseEmail)
	})

	t.Run("native anthropic invoke tool_use", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"Sending now."},{"type":"tool_use","id":"toolu_1","name":"send_email","input":{"to":"` + toolResponseEmail + `"}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
		req := nativeToolRequest("invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"email jane"}]}]}`)
		got, _ := executeToolResponse(t, req, body)
		out, cause := adapter.NativeMasker{}.MaskResponseWhy(body, got)
		require.Empty(t, cause)
		assert.Equal(t, toolResponseMask, toolResponseValue(t, out, "content", 1, "input", "to"))
		assert.Equal(t, "Sending now.", toolResponseValue(t, out, "content", 0, "text"))
		assert.NotContains(t, string(out), toolResponseEmail)
	})

	t.Run("canonical openai tool_calls", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"` + toolResponseEmail + `\"}"}}]},"finish_reason":"tool_calls"}]}`)
		got, stop := executeToolResponse(t, requestContext(), body)
		require.True(t, stop)
		args, ok := toolResponseValue(t, got, "choices", 0, "message", "tool_calls", 0, "function", "arguments").(string)
		require.True(t, ok)
		assert.JSONEq(t, `{"to":"`+toolResponseMask+`"}`, args)
		assert.NotContains(t, string(got), toolResponseEmail)
	})

	t.Run("canonical openai text and tool_calls", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Writing to ` + toolResponseEmail + `","tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"` + toolResponseEmail + `\"}"}}]},"finish_reason":"tool_calls"}]}`)
		got, _ := executeToolResponse(t, requestContext(), body)
		assert.Equal(t, "Writing to "+toolResponseMask, toolResponseValue(t, got, "choices", 0, "message", "content"))
		args, _ := toolResponseValue(t, got, "choices", 0, "message", "tool_calls", 0, "function", "arguments").(string)
		assert.JSONEq(t, `{"to":"`+toolResponseMask+`"}`, args)
	})
}

func TestResponseToolCallEchoOfAnotherLengthIsNotApplied(t *testing.T) {
	t.Parallel()
	body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi","tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"` + toolResponseEmail + `\"}"}}]},"finish_reason":"tool_calls"}]}`)
	f := &fakeGuard{response: GuardResponse{
		Status:             statusTransform,
		TransformedPayload: map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": "hi", "tool_calls": []any{}}}},
	}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, settings(""), requestContext(), &infracontext.ResponseContext{StatusCode: 200, Body: body}, event))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Nil(t, res.Body)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.True(t, extras.FailedOpen)
}

func TestResponseToolCallsWithLegacyInputEchoAreNotApplied(t *testing.T) {
	t.Parallel()
	legacy := map[string]any{"input": "Writing to " + toolResponseMask}
	openai := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Writing to ` + toolResponseEmail + `","tool_calls":[{"id":"call_1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"` + toolResponseEmail + `\"}"}}]},"finish_reason":"tool_calls"}]}`)
	converse := []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"Writing to ` + toolResponseEmail + `"},{"toolUse":{"toolUseId":"tooluse_1","name":"send_email","input":{"to":"` + toolResponseEmail + `"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}`)

	cases := []struct {
		name string
		req  *infracontext.RequestContext
		body []byte
	}{
		{"openai text and tool_calls", requestContext(), openai},
		{"native converse text and toolUse", nativeToolRequest("converse", `{"messages":[{"role":"user","content":[{"text":"email jane"}]}]}`), converse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusTransform, TransformedPayload: legacy}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, settings(""), tc.req, &infracontext.ResponseContext{StatusCode: 200, Body: tc.body}, event))
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Nil(t, res.Body, "a body that keeps the raw argument must not be returned as a transform")
			assert.False(t, res.StopUpstream)
			extras, ok := span.PluginAttrsCopy().Extras.(guardData)
			require.True(t, ok)
			assert.Equal(t, decisionFailedOpen, extras.Decision)
			assert.True(t, extras.FailedOpen)
			assert.True(t, extras.Degraded)
		})
	}
}
