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

package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeConverse(t *testing.T, body []byte) ConverseRequest {
	t.Helper()
	var req ConverseRequest
	require.NoError(t, json.Unmarshal(body, &req))
	return req
}

func topLevelKeys(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &keys))
	return keys
}

func TestBedrock_EncodeRequest_OpenAIText(t *testing.T) {
	input := `{
		"model": "amazon.nova-pro-v1:0",
		"messages": [
			{"role": "system", "content": "Be brief."},
			{"role": "user", "content": "Hello, Nova!"}
		],
		"max_tokens": 256,
		"temperature": 0.2,
		"stop": ["END"]
	}`

	out, err := NewRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatBedrock)
	require.NoError(t, err)

	keys := topLevelKeys(t, out)
	assert.NotContains(t, keys, "max_tokens")
	assert.NotContains(t, keys, "anthropic_version")
	assert.NotContains(t, keys, "model")

	req := decodeConverse(t, out)
	require.Len(t, req.System, 1)
	assert.Equal(t, "Be brief.", req.System[0].Text)
	require.Len(t, req.Messages, 1)
	assert.Equal(t, "user", req.Messages[0].Role)
	require.Len(t, req.Messages[0].Content, 1)
	assert.Equal(t, "Hello, Nova!", req.Messages[0].Content[0].Text)
	require.NotNil(t, req.InferenceConfig)
	assert.Equal(t, 256, req.InferenceConfig.MaxTokens)
	require.NotNil(t, req.InferenceConfig.Temperature)
	assert.InDelta(t, 0.2, *req.InferenceConfig.Temperature, 1e-9)
	assert.Equal(t, []string{"END"}, req.InferenceConfig.StopSequences)
	assert.Nil(t, req.ToolConfig)
}

func TestBedrock_EncodeRequest_IndependentOfModel(t *testing.T) {
	models := []string{
		"amazon.nova-pro-v1:0",
		"eu.amazon.nova-pro-v1:0",
		"anthropic.claude-3-5-sonnet-20241022-v2:0",
		"amazon.titan-text-express-v1",
		"meta.llama3-70b-instruct-v1:0",
		"arn:aws:bedrock:eu-west-1:065069198444:application-inference-profile/hfeskwe5y945",
		"",
	}

	var reference []byte
	for _, model := range models {
		body := `{"model":"` + model + `","messages":[{"role":"user","content":"Hello!"}]}`
		out, err := NewRegistry().AdaptRequest([]byte(body), FormatOpenAI, FormatBedrock)
		require.NoError(t, err, model)

		keys := topLevelKeys(t, out)
		assert.NotContains(t, keys, "max_tokens", model)
		assert.NotContains(t, keys, "anthropic_version", model)

		if reference == nil {
			reference = out
			continue
		}
		assert.JSONEq(t, string(reference), string(out),
			"the Converse body must not depend on the model ID (%s)", model)
	}
}

func TestBedrock_EncodeRequest_AnthropicIngress(t *testing.T) {
	input := `{
		"anthropic_version": "bedrock-2023-05-31",
		"system": "You are terse.",
		"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
		"max_tokens": 64
	}`

	out, err := NewRegistry().AdaptRequest([]byte(input), FormatAnthropic, FormatBedrock)
	require.NoError(t, err)

	keys := topLevelKeys(t, out)
	assert.NotContains(t, keys, "anthropic_version")
	assert.NotContains(t, keys, "max_tokens")

	req := decodeConverse(t, out)
	require.Len(t, req.System, 1)
	assert.Equal(t, "You are terse.", req.System[0].Text)
	require.NotNil(t, req.InferenceConfig)
	assert.Equal(t, 64, req.InferenceConfig.MaxTokens)
	require.Len(t, req.Messages, 1)
	assert.Equal(t, "hi", req.Messages[0].Content[0].Text)
}

func TestBedrock_EncodeRequest_Tools(t *testing.T) {
	const tools = `"tools": [{"type": "function", "function": {
		"name": "get_weather",
		"description": "Weather by city",
		"parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}
	}}]`

	tests := []struct {
		name       string
		toolChoice string
		assert     func(t *testing.T, cfg *ConverseToolConfig)
	}{
		{
			name:       "required becomes any",
			toolChoice: `"required"`,
			assert: func(t *testing.T, cfg *ConverseToolConfig) {
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.ToolChoice)
				assert.NotNil(t, cfg.ToolChoice.Any)
				assert.Nil(t, cfg.ToolChoice.Auto)
				assert.Nil(t, cfg.ToolChoice.Tool)
			},
		},
		{
			name:       "auto",
			toolChoice: `"auto"`,
			assert: func(t *testing.T, cfg *ConverseToolConfig) {
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.ToolChoice)
				assert.NotNil(t, cfg.ToolChoice.Auto)
			},
		},
		{
			name:       "named function",
			toolChoice: `{"type": "function", "function": {"name": "get_weather"}}`,
			assert: func(t *testing.T, cfg *ConverseToolConfig) {
				require.NotNil(t, cfg)
				require.NotNil(t, cfg.ToolChoice)
				require.NotNil(t, cfg.ToolChoice.Tool)
				assert.Equal(t, "get_weather", cfg.ToolChoice.Tool.Name)
			},
		},
		{
			name:       "none withholds the tools",
			toolChoice: `"none"`,
			assert: func(t *testing.T, cfg *ConverseToolConfig) {
				assert.Nil(t, cfg)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `{"messages":[{"role":"user","content":"weather?"}],` + tools + `,"tool_choice":` + tt.toolChoice + `}`
			out, err := NewRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatBedrock)
			require.NoError(t, err)

			req := decodeConverse(t, out)
			if req.ToolConfig != nil {
				require.Len(t, req.ToolConfig.Tools, 1)
				spec := req.ToolConfig.Tools[0].ToolSpec
				require.NotNil(t, spec)
				assert.Equal(t, "get_weather", spec.Name)
				assert.Equal(t, "Weather by city", spec.Description)
				assert.Equal(t, "object", spec.InputSchema.JSON["type"])
			}
			tt.assert(t, req.ToolConfig)
		})
	}
}

func TestBedrock_EncodeRequest_ToolLoopMergesResultsIntoOneUserTurn(t *testing.T) {
	input := `{
		"messages": [
			{"role": "user", "content": "weather in two cities"},
			{"role": "assistant", "content": "Checking.", "tool_calls": [
				{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Madrid\"}"}},
				{"id": "call_2", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Oslo\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
			{"role": "tool", "tool_call_id": "call_2", "content": "snow"}
		]
	}`

	out, err := NewRegistry().AdaptRequest([]byte(input), FormatOpenAI, FormatBedrock)
	require.NoError(t, err)

	req := decodeConverse(t, out)
	require.Len(t, req.Messages, 3, "user, assistant, then one user turn with both results")

	assistant := req.Messages[1]
	assert.Equal(t, "assistant", assistant.Role)
	require.Len(t, assistant.Content, 3)
	assert.Equal(t, "Checking.", assistant.Content[0].Text)
	require.NotNil(t, assistant.Content[1].ToolUse)
	assert.Equal(t, "call_1", assistant.Content[1].ToolUse.ToolUseID)
	assert.Equal(t, "get_weather", assistant.Content[1].ToolUse.Name)
	assert.JSONEq(t, `{"city":"Madrid"}`, string(assistant.Content[1].ToolUse.Input))

	results := req.Messages[2]
	assert.Equal(t, "user", results.Role)
	require.Len(t, results.Content, 2)
	require.NotNil(t, results.Content[0].ToolResult)
	assert.Equal(t, "call_1", results.Content[0].ToolResult.ToolUseID)
	assert.Equal(t, "sunny", results.Content[0].ToolResult.Content[0].Text)
	require.NotNil(t, results.Content[1].ToolResult)
	assert.Equal(t, "call_2", results.Content[1].ToolResult.ToolUseID)
}

func TestBedrock_EncodeRequest_MergesConsecutiveSameRoleTurns(t *testing.T) {
	req := &CanonicalRequest{Messages: []CanonicalMessage{
		{Role: "user", Content: "first"},
		{Role: "user", Content: "second"},
		{Role: "assistant", Content: "reply"},
	}}

	out, err := (&BedrockAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	wire := decodeConverse(t, out)
	require.Len(t, wire.Messages, 2)
	require.Len(t, wire.Messages[0].Content, 2)
	assert.Equal(t, "first", wire.Messages[0].Content[0].Text)
	assert.Equal(t, "second", wire.Messages[0].Content[1].Text)
	assert.Equal(t, "assistant", wire.Messages[1].Role)
}

func TestBedrock_EncodeRequest_DropsEmptyTurns(t *testing.T) {
	req := &CanonicalRequest{Messages: []CanonicalMessage{
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: ""},
		{Role: "user", Content: "still there?"},
	}}

	out, err := (&BedrockAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	wire := decodeConverse(t, out)
	require.Len(t, wire.Messages, 1, "the empty assistant turn is dropped and the user turns merge")
	require.Len(t, wire.Messages[0].Content, 2)
}

func TestBedrock_EncodeRequest_MalformedToolArgumentsBecomeEmptyObject(t *testing.T) {
	req := &CanonicalRequest{Messages: []CanonicalMessage{{
		Role:      "assistant",
		ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "noop", Arguments: `{"city": `}},
	}}}

	out, err := (&BedrockAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	wire := decodeConverse(t, out)
	require.Len(t, wire.Messages, 1)
	require.NotNil(t, wire.Messages[0].Content[0].ToolUse)
	assert.JSONEq(t, `{}`, string(wire.Messages[0].Content[0].ToolUse.Input))
}

func TestBedrock_DecodeRequest(t *testing.T) {
	body := `{
		"system": [{"text": "Be brief."}],
		"messages": [
			{"role": "user", "content": [{"text": "weather?"}]},
			{"role": "assistant", "content": [
				{"text": "Checking."},
				{"toolUse": {"toolUseId": "call_1", "name": "get_weather", "input": {"city": "Madrid"}}}
			]},
			{"role": "user", "content": [{"toolResult": {"toolUseId": "call_1", "content": [{"json": {"temp": 30}}]}}]}
		],
		"inferenceConfig": {"maxTokens": 128, "topP": 0.9, "stopSequences": ["END"]},
		"toolConfig": {
			"tools": [{"toolSpec": {"name": "get_weather", "inputSchema": {"json": {"type": "object"}}}}],
			"toolChoice": {"tool": {"name": "get_weather"}}
		}
	}`

	cr, err := (&BedrockAdapter{}).DecodeRequest([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "Be brief.", cr.System)
	require.Len(t, cr.Messages, 3)
	assert.Equal(t, "weather?", cr.Messages[0].Content)
	assert.Equal(t, "Checking.", cr.Messages[1].Content)
	require.Len(t, cr.Messages[1].ToolCalls, 1)
	assert.Equal(t, "call_1", cr.Messages[1].ToolCalls[0].ID)
	assert.JSONEq(t, `{"city":"Madrid"}`, cr.Messages[1].ToolCalls[0].Arguments)
	assert.Equal(t, "tool", cr.Messages[2].Role)
	assert.Equal(t, "call_1", cr.Messages[2].ToolCallID)
	assert.JSONEq(t, `{"temp":30}`, cr.Messages[2].Content)
	assert.Equal(t, 128, cr.MaxTokens)
	require.NotNil(t, cr.TopP)
	assert.InDelta(t, 0.9, *cr.TopP, 1e-9)
	assert.Equal(t, []string{"END"}, cr.Stop)
	require.Len(t, cr.Tools, 1)
	assert.Equal(t, "get_weather", cr.Tools[0].Name)
	require.NotNil(t, cr.ToolChoice)
	assert.Equal(t, "tool", cr.ToolChoice.Type)
	assert.Equal(t, "get_weather", cr.ToolChoice.Name)
}

func TestBedrock_DecodeRequest_ReadsGraftedModelAndStream(t *testing.T) {
	body := `{"model":"amazon.nova-pro-v1:0","stream":true,"messages":[{"role":"user","content":[{"text":"hi"}]}]}`

	cr, err := (&BedrockAdapter{}).DecodeRequest([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "amazon.nova-pro-v1:0", cr.Model)
	assert.True(t, cr.Stream)
}

func TestBedrock_DecodeRequest_ToolResultsPrecedeTextAndKeepErrors(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[
		{"text":"and now?"},
		{"toolResult":{"toolUseId":"call_1","status":"error","content":[{"text":"timeout"}]}}
	]}]}`

	cr, err := (&BedrockAdapter{}).DecodeRequest([]byte(body))
	require.NoError(t, err)

	require.Len(t, cr.Messages, 2)
	assert.Equal(t, "tool", cr.Messages[0].Role, "results answer the previous assistant turn, so they come first")
	assert.Equal(t, "error: timeout", cr.Messages[0].Content)
	assert.Equal(t, "user", cr.Messages[1].Role)
	assert.Equal(t, "and now?", cr.Messages[1].Content)
}

func TestBedrock_EncodeRequest_NoneKeepsToolsWhenConversationUsesThem(t *testing.T) {
	req := &CanonicalRequest{
		Messages: []CanonicalMessage{
			{Role: "user", Content: "weather?"},
			{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Madrid"}`}}},
			{Role: "tool", ToolCallID: "call_1", Content: "sunny"},
		},
		Tools:      []CanonicalTool{{Name: "get_weather"}},
		ToolChoice: &CanonicalToolChoice{Type: "none"},
	}

	out, err := (&BedrockAdapter{}).EncodeRequest(req)
	require.NoError(t, err)

	wire := decodeConverse(t, out)
	require.NotNil(t, wire.ToolConfig, "toolUse/toolResult blocks are invalid without a toolConfig")
	require.Len(t, wire.ToolConfig.Tools, 1)
	assert.Nil(t, wire.ToolConfig.ToolChoice, "none relaxes to the default choice")
}

func TestBedrock_DecodeResponse(t *testing.T) {
	body := `{
		"output": {"message": {"role": "assistant", "content": [
			{"reasoningContent": {"reasoningText": {"text": "They want the weather.", "signature": "sig"}}},
			{"text": "Let me check."},
			{"toolUse": {"toolUseId": "call_1", "name": "get_weather", "input": {"city": "Madrid"}}}
		]}},
		"stopReason": "tool_use",
		"usage": {"inputTokens": 12, "outputTokens": 7, "totalTokens": 19, "cacheReadInputTokens": 4, "cacheWriteInputTokens": 2},
		"metrics": {"latencyMs": 321}
	}`

	cr, err := (&BedrockAdapter{}).DecodeResponse([]byte(body))
	require.NoError(t, err)

	assert.Equal(t, "assistant", cr.Role)
	assert.Equal(t, "Let me check.", cr.Content)
	assert.Equal(t, "tool_calls", cr.FinishReason)
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "call_1", cr.ToolCalls[0].ID)
	assert.Equal(t, "get_weather", cr.ToolCalls[0].Name)
	assert.JSONEq(t, `{"city":"Madrid"}`, cr.ToolCalls[0].Arguments)
	require.NotNil(t, cr.Reasoning)
	assert.Equal(t, "They want the weather.", cr.Reasoning.ThinkingText)
	assert.Equal(t, &CanonicalUsage{
		InputTokens:           18,
		OutputTokens:          7,
		TotalTokens:           25,
		CachedInputTokens:     4,
		CacheWriteInputTokens: 2,
	}, cr.Usage)
}

func TestBedrock_UsageFold(t *testing.T) {
	tests := []struct {
		name string
		wire string
		want *CanonicalUsage
	}{
		{
			name: "read and write fold into input and total",
			wire: `{"inputTokens":12,"outputTokens":7,"totalTokens":19,"cacheReadInputTokens":4,"cacheWriteInputTokens":2}`,
			want: &CanonicalUsage{InputTokens: 18, OutputTokens: 7, TotalTokens: 25, CachedInputTokens: 4, CacheWriteInputTokens: 2},
		},
		{
			name: "total already covering the cache is kept",
			wire: `{"inputTokens":12,"outputTokens":7,"totalTokens":30,"cacheReadInputTokens":4,"cacheWriteInputTokens":2}`,
			want: &CanonicalUsage{InputTokens: 18, OutputTokens: 7, TotalTokens: 30, CachedInputTokens: 4, CacheWriteInputTokens: 2},
		},
		{
			name: "1h details split the write",
			wire: `{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheWriteInputTokens":300,
				"cacheDetails":[{"inputTokens":200,"ttl":"1h"},{"inputTokens":100,"ttl":"5m"}]}`,
			want: &CanonicalUsage{InputTokens: 310, OutputTokens: 5, TotalTokens: 315, CacheWriteInputTokens: 300, CacheWrite1hInputTokens: 200},
		},
		{
			name: "1h share never exceeds the write",
			wire: `{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheWriteInputTokens":50,
				"cacheDetails":[{"inputTokens":200,"ttl":"1h"}]}`,
			want: &CanonicalUsage{InputTokens: 60, OutputTokens: 5, TotalTokens: 65, CacheWriteInputTokens: 50, CacheWrite1hInputTokens: 50},
		},
		{
			name: "unknown or empty ttl entries are ignored for 1h",
			wire: `{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheWriteInputTokens":300,
				"cacheDetails":[{"inputTokens":100,"ttl":""},{"inputTokens":150,"ttl":"24h"},{"inputTokens":50}]}`,
			want: &CanonicalUsage{InputTokens: 310, OutputTokens: 5, TotalTokens: 315, CacheWriteInputTokens: 300},
		},
		{
			name: "multiple 1h entries are summed",
			wire: `{"inputTokens":10,"outputTokens":5,"totalTokens":15,"cacheWriteInputTokens":300,
				"cacheDetails":[{"inputTokens":200,"ttl":"1h"},{"inputTokens":50,"ttl":"1h"},{"inputTokens":50,"ttl":"5m"}]}`,
			want: &CanonicalUsage{InputTokens: 310, OutputTokens: 5, TotalTokens: 315, CacheWriteInputTokens: 300, CacheWrite1hInputTokens: 250},
		},
		{
			name: "cache-only usage is not dropped",
			wire: `{"inputTokens":0,"outputTokens":0,"totalTokens":0,"cacheReadInputTokens":40}`,
			want: &CanonicalUsage{InputTokens: 40, TotalTokens: 40, CachedInputTokens: 40},
		},
		{
			name: "no cache leaves the counts untouched",
			wire: `{"inputTokens":5,"outputTokens":9,"totalTokens":14}`,
			want: &CanonicalUsage{InputTokens: 5, OutputTokens: 9, TotalTokens: 14},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffered, err := (&BedrockAdapter{}).DecodeResponse([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":` + tt.wire + `}`))
			require.NoError(t, err)
			assert.Equal(t, tt.want, buffered.Usage, "buffered")
			assertUsageInvariants(t, buffered.Usage)

			chunk, err := (&BedrockAdapter{}).DecodeStreamChunk([]byte(`{"metadata":{"usage":` + tt.wire + `}}`))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			streamed := MergeUsage(nil, chunk.Usage)
			assert.Equal(t, tt.want, streamed, "stream")
			assertUsageInvariants(t, streamed)
		})
	}
}

func assertUsageInvariants(t *testing.T, u *CanonicalUsage) {
	t.Helper()
	require.NotNil(t, u)
	assert.LessOrEqual(t, u.CachedInputTokens+u.CacheWriteInputTokens, u.InputTokens, "R+W<=I")
	assert.LessOrEqual(t, u.CacheWrite1hInputTokens, u.CacheWriteInputTokens, "W1h<=W")
	assert.GreaterOrEqual(t, u.TotalTokens, u.InputTokens+u.OutputTokens, "Total>=I+O")
}

func TestBedrock_UsageUnfold(t *testing.T) {
	tests := []struct {
		name       string
		usage      *CanonicalUsage
		want       *ConverseUsage
		roundTrips bool
	}{
		{
			name: "consistent usage splits the write by ttl",
			usage: &CanonicalUsage{
				InputTokens: 318, OutputTokens: 7, TotalTokens: 325,
				CachedInputTokens: 4, CacheWriteInputTokens: 300, CacheWrite1hInputTokens: 200,
			},
			want: &ConverseUsage{
				InputTokens: 14, OutputTokens: 7, TotalTokens: 325,
				CacheReadInputTokens: 4, CacheWriteInputTokens: 300,
				CacheDetails: []ConverseCacheDetail{{InputTokens: 200, TTL: "1h"}, {InputTokens: 100, TTL: "5m"}},
			},
			roundTrips: true,
		},
		{
			name:  "five-minute-only write",
			usage: &CanonicalUsage{InputTokens: 110, OutputTokens: 5, TotalTokens: 115, CacheWriteInputTokens: 100},
			want: &ConverseUsage{
				InputTokens: 10, OutputTokens: 5, TotalTokens: 115, CacheWriteInputTokens: 100,
				CacheDetails: []ConverseCacheDetail{{InputTokens: 100, TTL: "5m"}},
			},
			roundTrips: true,
		},
		{
			name:       "read-only",
			usage:      &CanonicalUsage{InputTokens: 50, OutputTokens: 3, TotalTokens: 53, CachedInputTokens: 40},
			want:       &ConverseUsage{InputTokens: 10, OutputTokens: 3, TotalTokens: 53, CacheReadInputTokens: 40},
			roundTrips: true,
		},
		{
			name:       "no cache",
			usage:      &CanonicalUsage{InputTokens: 5, OutputTokens: 9, TotalTokens: 14},
			want:       &ConverseUsage{InputTokens: 5, OutputTokens: 9, TotalTokens: 14},
			roundTrips: true,
		},
		{
			name:  "1h share above the write is clamped",
			usage: &CanonicalUsage{InputTokens: 60, OutputTokens: 5, TotalTokens: 65, CacheWriteInputTokens: 50, CacheWrite1hInputTokens: 200},
			want: &ConverseUsage{
				InputTokens: 10, OutputTokens: 5, TotalTokens: 65, CacheWriteInputTokens: 50,
				CacheDetails: []ConverseCacheDetail{{InputTokens: 50, TTL: "1h"}},
			},
		},
		{
			name:  "cache above the input never goes negative",
			usage: &CanonicalUsage{InputTokens: 10, OutputTokens: 2, TotalTokens: 12, CachedInputTokens: 8, CacheWriteInputTokens: 5},
			want: &ConverseUsage{
				InputTokens: 0, OutputTokens: 2, TotalTokens: 12, CacheReadInputTokens: 8, CacheWriteInputTokens: 5,
				CacheDetails: []ConverseCacheDetail{{InputTokens: 5, TTL: "5m"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &BedrockAdapter{}

			buffered, err := a.EncodeResponse(&CanonicalResponse{Role: "assistant", Content: "ok", FinishReason: "stop", Usage: tt.usage})
			require.NoError(t, err)
			var wire ConverseResponse
			require.NoError(t, json.Unmarshal(buffered, &wire))
			assert.Equal(t, tt.want, wire.Usage, "buffered wire")

			lines, err := a.EncodeStreamChunk(&CanonicalStreamChunk{Usage: tt.usage})
			require.NoError(t, err)
			require.NotEmpty(t, lines)
			var event ConverseStreamEvent
			require.NoError(t, json.Unmarshal(bytes.TrimPrefix(lines[0], []byte("data: ")), &event))
			require.NotNil(t, event.Metadata)
			assert.Equal(t, tt.want, event.Metadata.Usage, "stream wire")

			if !tt.roundTrips {
				return
			}
			back, err := a.DecodeResponse(buffered)
			require.NoError(t, err)
			assert.Equal(t, tt.usage, back.Usage, "buffered round trip")

			chunk, err := a.DecodeStreamChunk(bytes.TrimPrefix(lines[0], []byte("data: ")))
			require.NoError(t, err)
			require.NotNil(t, chunk)
			assert.Equal(t, tt.usage, chunk.Usage, "stream round trip")
		})
	}
}

func TestBedrock_DecodeResponse_StopReasons(t *testing.T) {
	tests := map[string]string{
		"end_turn":                      "stop",
		"stop_sequence":                 "stop",
		"max_tokens":                    "length",
		"model_context_window_exceeded": "model_context_window_exceeded",
		"tool_use":                      "tool_calls",
		"guardrail_intervened":          "content_filter",
		"content_filtered":              "content_filter",
		"malformed_model_output":        "malformed_model_output",
	}
	for stop, want := range tests {
		t.Run(stop, func(t *testing.T) {
			body := `{"output":{"message":{"role":"assistant","content":[{"text":"x"}]}},"stopReason":"` + stop + `"}`
			cr, err := (&BedrockAdapter{}).DecodeResponse([]byte(body))
			require.NoError(t, err)
			assert.Equal(t, want, cr.FinishReason)
		})
	}
}

func TestBedrock_EncodeResponse_RoundTrip(t *testing.T) {
	in := &CanonicalResponse{
		Role:         "assistant",
		Content:      "Let me check.",
		FinishReason: "tool_calls",
		ToolCalls:    []CanonicalToolCall{{ID: "call_1", Name: "get_weather", Arguments: `{"city":"Madrid"}`}},
		Reasoning:    &CanonicalReasoning{ThinkingText: "thinking"},
		Usage:        &CanonicalUsage{InputTokens: 3, OutputTokens: 4, TotalTokens: 7, CachedInputTokens: 1},
	}

	body, err := (&BedrockAdapter{}).EncodeResponse(in)
	require.NoError(t, err)

	var wire ConverseResponse
	require.NoError(t, json.Unmarshal(body, &wire))
	assert.Equal(t, "tool_use", wire.StopReason)
	require.NotNil(t, wire.Output.Message)
	require.Len(t, wire.Output.Message.Content, 3)
	require.NotNil(t, wire.Output.Message.Content[0].ReasoningContent)
	assert.Equal(t, "Let me check.", wire.Output.Message.Content[1].Text)
	require.NotNil(t, wire.Output.Message.Content[2].ToolUse)
	require.NotNil(t, wire.Usage)
	assert.Equal(t, 1, wire.Usage.CacheReadInputTokens)

	back, err := (&BedrockAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	assert.Equal(t, in.Content, back.Content)
	assert.Equal(t, in.FinishReason, back.FinishReason)
	assert.Equal(t, in.ToolCalls[0].ID, back.ToolCalls[0].ID)
	assert.JSONEq(t, in.ToolCalls[0].Arguments, back.ToolCalls[0].Arguments)
	assert.Equal(t, in.Reasoning.ThinkingText, back.Reasoning.ThinkingText)
	assert.Equal(t, in.Usage, back.Usage)
}

func TestBedrock_EncodeResponse_StopMarksToolUse(t *testing.T) {
	body, err := (&BedrockAdapter{}).EncodeResponse(&CanonicalResponse{
		FinishReason: "stop",
		ToolCalls:    []CanonicalToolCall{{ID: "call_1", Name: "noop", Arguments: "{}"}},
	})
	require.NoError(t, err)

	var wire ConverseResponse
	require.NoError(t, json.Unmarshal(body, &wire))
	assert.Equal(t, "tool_use", wire.StopReason)
}

func TestBedrock_DecodeStreamChunk(t *testing.T) {
	tests := []struct {
		name  string
		chunk string
		want  *CanonicalStreamChunk
	}{
		{
			name:  "message start opens the assistant turn",
			chunk: `{"messageStart":{"role":"assistant"}}`,
			want:  &CanonicalStreamChunk{Role: "assistant"},
		},
		{
			name:  "text delta",
			chunk: `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Hel"}}}`,
			want:  &CanonicalStreamChunk{Delta: "Hel"},
		},
		{
			name:  "reasoning delta",
			chunk: `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"hmm"}}}}`,
			want:  &CanonicalStreamChunk{ReasoningDelta: "hmm"},
		},
		{
			name:  "reasoning signature says nothing",
			chunk: `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"reasoningContent":{"signature":"sig"}}}}`,
			want:  nil,
		},
		{
			name:  "tool use start names the tool",
			chunk: `{"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call_1","name":"get_weather"}}}}`,
			want:  &CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ID: "call_1", Name: "get_weather"}}},
		},
		{
			name:  "tool use delta streams arguments",
			chunk: `{"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"city\":"}}}}`,
			want:  &CanonicalStreamChunk{ToolCallDeltas: []StreamToolCallDelta{{Index: 1, ArgumentsDelta: `{"city":`}}},
		},
		{
			name:  "content block stop is silent",
			chunk: `{"contentBlockStop":{"contentBlockIndex":0}}`,
			want:  nil,
		},
		{
			name:  "message stop carries the finish reason",
			chunk: `{"messageStop":{"stopReason":"max_tokens"}}`,
			want:  &CanonicalStreamChunk{FinishReason: "length"},
		},
		{
			name:  "metadata carries usage",
			chunk: `{"metadata":{"usage":{"inputTokens":5,"outputTokens":9,"totalTokens":14},"metrics":{"latencyMs":100}}}`,
			want:  &CanonicalStreamChunk{Usage: &CanonicalUsage{InputTokens: 5, OutputTokens: 9, TotalTokens: 14}},
		},
		{
			name:  "unknown event is skipped",
			chunk: `{"somethingNew":{}}`,
			want:  nil,
		},
		{
			name:  "non-JSON is skipped",
			chunk: `not json`,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&BedrockAdapter{}).DecodeStreamChunk([]byte(tt.chunk))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBedrock_EncodeStreamChunk(t *testing.T) {
	lines, err := (&BedrockAdapter{}).EncodeStreamChunk(&CanonicalStreamChunk{
		Role:  "assistant",
		Delta: "Hi",
		ToolCallDeltas: []StreamToolCallDelta{
			{Index: 1, ID: "call_1", Name: "get_weather"},
			{Index: 1, ArgumentsDelta: `{"city":"Madrid"}`},
		},
		FinishReason: "tool_calls",
		Usage:        &CanonicalUsage{InputTokens: 1, OutputTokens: 2, TotalTokens: 3},
	})
	require.NoError(t, err)

	var events []ConverseStreamEvent
	for i := 0; i < len(lines); i += 2 {
		require.True(t, len(lines[i]) > 6 && string(lines[i][:6]) == "data: ", "line %d: %q", i, lines[i])
		assert.Empty(t, lines[i+1], "every data line is followed by a blank separator")
		var ev ConverseStreamEvent
		require.NoError(t, json.Unmarshal(lines[i][6:], &ev))
		events = append(events, ev)
	}

	require.Len(t, events, 6)
	assert.Equal(t, "assistant", events[0].MessageStart.Role)
	assert.Equal(t, "Hi", events[1].ContentBlockDelta.Delta.Text)
	assert.Equal(t, "call_1", events[2].ContentBlockStart.Start.ToolUse.ToolUseID)
	assert.Equal(t, 1, events[2].ContentBlockStart.ContentBlockIndex)
	assert.Equal(t, `{"city":"Madrid"}`, events[3].ContentBlockDelta.Delta.ToolUse.Input)
	assert.Equal(t, "tool_use", events[4].MessageStop.StopReason)
	assert.Equal(t, 3, events[5].Metadata.Usage.TotalTokens)
}

func TestBedrock_EncodeStreamChunk_EmptyChunkEmitsNothing(t *testing.T) {
	lines, err := (&BedrockAdapter{}).EncodeStreamChunk(&CanonicalStreamChunk{})
	require.NoError(t, err)
	assert.Empty(t, lines)
}

func TestBedrock_AdaptResponseToOpenAI(t *testing.T) {
	body := `{
		"output": {"message": {"role": "assistant", "content": [{"text": "Hello from Nova"}]}},
		"stopReason": "end_turn",
		"usage": {"inputTokens": 3, "outputTokens": 4, "totalTokens": 7}
	}`

	out, err := NewRegistry().AdaptResponse([]byte(body), FormatOpenAI, FormatBedrock)
	require.NoError(t, err)

	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	require.Len(t, resp.Choices, 1)
	assert.Equal(t, "Hello from Nova", resp.Choices[0].Message.Content)
	assert.Equal(t, "stop", resp.Choices[0].FinishReason)
	assert.Equal(t, 7, resp.Usage.TotalTokens)
}

func TestBedrock_AdaptStreamToOpenAI_ToolCall(t *testing.T) {
	events := []string{
		`{"messageStart":{"role":"assistant"}}`,
		`{"contentBlockStart":{"contentBlockIndex":0,"start":{}}}`,
		`{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Checking."}}}`,
		`{"contentBlockStop":{"contentBlockIndex":0}}`,
		`{"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call_1","name":"get_weather"}}}}`,
		`{"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"city\":"}}}}`,
		`{"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"\"Madrid\"}"}}}}`,
		`{"contentBlockStop":{"contentBlockIndex":1}}`,
		`{"messageStop":{"stopReason":"tool_use"}}`,
		`{"metadata":{"usage":{"inputTokens":5,"outputTokens":9,"totalTokens":14}}}`,
	}

	type openAIChunk struct {
		Choices []struct {
			Delta struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					Index    int    `json:"index"`
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}

	var (
		content, arguments, toolID, toolName string
		finish                               string
		totalTokens                          int
	)
	for _, ev := range events {
		lines, err := NewRegistry().AdaptStreamChunk([]byte(ev), FormatOpenAI, FormatBedrock)
		require.NoError(t, err, ev)
		for _, line := range lines {
			if len(line) == 0 {
				continue
			}
			require.True(t, strings.HasPrefix(string(line), "data: "), "%q", line)
			var chunk openAIChunk
			require.NoError(t, json.Unmarshal(line[6:], &chunk), "%q", line)
			if chunk.Usage != nil {
				totalTokens = chunk.Usage.TotalTokens
			}
			if len(chunk.Choices) == 0 {
				continue
			}
			choice := chunk.Choices[0]
			content += choice.Delta.Content
			for _, tc := range choice.Delta.ToolCalls {
				if tc.ID != "" {
					toolID = tc.ID
				}
				if tc.Function.Name != "" {
					toolName = tc.Function.Name
				}
				arguments += tc.Function.Arguments
			}
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				finish = *choice.FinishReason
			}
		}
	}

	assert.Equal(t, "Checking.", content)
	assert.Equal(t, "call_1", toolID)
	assert.Equal(t, "get_weather", toolName)
	assert.JSONEq(t, `{"city":"Madrid"}`, arguments)
	assert.Equal(t, "tool_calls", finish)
	assert.Equal(t, 14, totalTokens)
}

func TestBedrock_EncodeRequest_Images(t *testing.T) {
	t.Parallel()

	pngBytes := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

	formats := []struct {
		mediaType string
		format    string
	}{
		{mediaType: "image/png", format: "png"},
		{mediaType: "image/jpeg", format: "jpeg"},
		{mediaType: "image/gif", format: "gif"},
		{mediaType: "image/webp", format: "webp"},
		{mediaType: "image/tiff", format: "tiff"},
	}
	for _, tt := range formats {
		t.Run(tt.format, func(t *testing.T) {
			t.Parallel()

			out, err := (&BedrockAdapter{}).EncodeRequest(&CanonicalRequest{Messages: []CanonicalMessage{{
				Role:    "user",
				Content: "describe",
				Images:  []CanonicalImage{{MediaType: tt.mediaType, Data: "iVBORw0KGgo=", Detail: "high"}},
			}}})
			require.NoError(t, err)

			req := decodeConverse(t, out)
			require.Len(t, req.Messages, 1)
			blocks := req.Messages[0].Content
			require.Len(t, blocks, 2)
			require.NotNil(t, blocks[0].Image)
			assert.Equal(t, tt.format, blocks[0].Image.Format)
			assert.Equal(t, pngBytes, blocks[0].Image.Source.Bytes)
			assert.Equal(t, "describe", blocks[1].Text)
		})
	}

	failures := []struct {
		name     string
		image    CanonicalImage
		secret   string
		wantText string
	}{
		{name: "https url", image: CanonicalImage{URL: "https://example.com/private-cat.jpg"}, secret: "private-cat", wantText: "inline base64 image data"},
		{name: "missing media type", image: CanonicalImage{Data: "U0VDUkVU"}, secret: "U0VDUkVU", wantText: "image media type is missing or not an image/* type"},
		{name: "non-image media type", image: CanonicalImage{MediaType: "application/pdf", Data: "U0VDUkVU"}, secret: "pdf", wantText: "image media type is missing or not an image/* type"},
		{name: "invalid base64", image: CanonicalImage{MediaType: "image/png", Data: "@@@SECRET"}, secret: "SECRET", wantText: "not valid base64"},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := (&BedrockAdapter{}).EncodeRequest(&CanonicalRequest{Messages: []CanonicalMessage{{
				Role:   "user",
				Images: []CanonicalImage{tt.image},
			}}})

			require.ErrorIs(t, err, ErrUnsupportedContent)
			var contentErr *UnsupportedContentError
			require.ErrorAs(t, err, &contentErr)
			assert.Contains(t, err.Error(), tt.wantText)
			assert.NotContains(t, err.Error(), tt.secret)
			assert.NotContains(t, err.Error(), "bedrock")
		})
	}
}

func TestBedrock_EncodeRequest_ToolResultThenImageTurnMergeIntoOneUserTurn(t *testing.T) {
	t.Parallel()

	out, err := (&BedrockAdapter{}).EncodeRequest(&CanonicalRequest{Messages: []CanonicalMessage{
		{Role: "user", Content: "look it up"},
		{Role: "assistant", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "fetch_image", Arguments: `{}`}}},
		{Role: "tool", ToolCallID: "call_1", Content: "done"},
		{Role: "user", Content: "what is it?", Images: []CanonicalImage{{MediaType: "image/png", Data: "iVBORw0KGgo="}}},
	}})
	require.NoError(t, err)

	req := decodeConverse(t, out)
	require.Len(t, req.Messages, 3)
	turn := req.Messages[2]
	assert.Equal(t, "user", turn.Role)
	require.Len(t, turn.Content, 3)
	require.NotNil(t, turn.Content[0].ToolResult)
	assert.Equal(t, "call_1", turn.Content[0].ToolResult.ToolUseID)
	require.NotNil(t, turn.Content[1].Image)
	assert.Equal(t, "png", turn.Content[1].Image.Format)
	assert.Equal(t, "what is it?", turn.Content[2].Text)
}

func TestBedrock_EncodeRequest_ImagesOnlyOnUserMessages(t *testing.T) {
	t.Parallel()

	out, err := (&BedrockAdapter{}).EncodeRequest(&CanonicalRequest{Messages: []CanonicalMessage{{
		Role:    "assistant",
		Content: "ok",
		Images:  []CanonicalImage{{URL: "https://example.com/a.png"}},
	}}})
	require.NoError(t, err)

	req := decodeConverse(t, out)
	require.Len(t, req.Messages, 1)
	assert.Equal(t, []ConverseContentBlock{{Text: "ok"}}, req.Messages[0].Content)
}

func TestBedrock_DecodeRequest_Image(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want []CanonicalMessage
	}{
		{
			name: "image with text",
			body: `{"messages":[{"role":"user","content":[{"image":{"format":"jpeg","source":{"bytes":"/9j/4AAQ"}}},{"text":"what is it?"}]}]}`,
			want: []CanonicalMessage{{
				Role:    "user",
				Content: "what is it?",
				Images:  []CanonicalImage{{MediaType: "image/jpeg", Data: "/9j/4AAQ"}},
			}},
		},
		{
			name: "image only",
			body: `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"iVBORw0KGgo="}}}]}]}`,
			want: []CanonicalMessage{{
				Role:   "user",
				Images: []CanonicalImage{{MediaType: "image/png", Data: "iVBORw0KGgo="}},
			}},
		},
		{
			name: "s3 location ignored",
			body: `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"s3Location":{"uri":"s3://b/k"}}}},{"text":"hi"}]}]}`,
			want: []CanonicalMessage{{Role: "user", Content: "hi"}},
		},
		{
			name: "tool result precedes image turn",
			body: `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"iVBORw0KGgo="}}},{"toolResult":{"toolUseId":"call_1","content":[{"text":"42"}]}}]}]}`,
			want: []CanonicalMessage{
				{Role: "tool", ToolCallID: "call_1", Content: "42"},
				{Role: "user", Images: []CanonicalImage{{MediaType: "image/png", Data: "iVBORw0KGgo="}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cr, err := (&BedrockAdapter{}).DecodeRequest([]byte(tt.body))
			require.NoError(t, err)

			assert.Equal(t, tt.want, cr.Messages)
		})
	}
}
