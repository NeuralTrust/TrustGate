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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Canonical roundtrip: OpenAI → Canonical → OpenAI
// ---------------------------------------------------------------------------

func TestCanonical_OpenAI_Roundtrip(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are helpful."},
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	adapter := &OpenAIAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)
	assert.Len(t, canonical.Messages, 1) // system extracted
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, 100, canonical.MaxTokens)
	assert.Equal(t, 0.7, *canonical.Temperature)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system re-injected + user
	assert.Equal(t, "system", msgs[0].(map[string]interface{})["role"])
}

// ---------------------------------------------------------------------------
// Response roundtrip: OpenAI → Canonical → OpenAI
// ---------------------------------------------------------------------------

func TestCanonical_OpenAI_ResponseRoundtrip(t *testing.T) {
	input := `{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"model": "gpt-4",
		"choices": [
			{
				"index": 0,
				"message": {"role": "assistant", "content": "Hello!"},
				"finish_reason": "stop"
			}
		],
		"usage": {
			"prompt_tokens": 5,
			"completion_tokens": 3,
			"total_tokens": 8
		}
	}`

	adapter := &OpenAIAdapter{}
	canonical, err := adapter.DecodeResponse([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "chatcmpl-123", canonical.ID)
	assert.Equal(t, "Hello!", canonical.Content)
	assert.Equal(t, "stop", canonical.FinishReason)
	assert.Equal(t, 8, canonical.Usage.TotalTokens)

	encoded, err := adapter.EncodeResponse(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "chat.completion", result["object"])
}

func TestUsageExtraction_OpenAICompletions(t *testing.T) {
	runUsageCases(t, &OpenAIAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 12, OutputTokens: 8, TotalTokens: 20},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			name:      "stream final chunk with usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 12, OutputTokens: 8, TotalTokens: 20},
		},
		{
			name:      "stream no usage",
			body:      []byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hi"}}]}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestUsageSubCounts_OpenAIChat_CachedInput(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20,"prompt_tokens_details":{"cached_tokens":7}}}`)
	cr, err := (&OpenAIAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 7, cr.Usage.CachedInputTokens)
	assert.Equal(t, 12, cr.Usage.InputTokens, "CachedInputTokens is a sub-count; InputTokens must not be reduced")
}

func TestUsageSubCounts_OpenAIChat_ReasoningOutput(t *testing.T) {
	body := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":20,"total_tokens":25,"completion_tokens_details":{"reasoning_tokens":12}}}`)
	cr, err := (&OpenAIAdapter{}).DecodeResponse(body)
	require.NoError(t, err)
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 12, cr.Usage.ReasoningOutputTokens)
	assert.Equal(t, 20, cr.Usage.OutputTokens, "ReasoningOutputTokens is a sub-count; OutputTokens must not be reduced")
}

func TestCanonical_OpenAI_Completions_DeveloperAndRefusal(t *testing.T) {
	a := &OpenAIAdapter{}
	req := `{
		"model":"gpt-5-mini",
		"messages":[
			{"role":"developer","content":"Prefer tools."},
			{"role":"user","content":"hi"}
		]
	}`
	cr, err := a.DecodeRequest([]byte(req))
	require.NoError(t, err)
	assert.Equal(t, "Prefer tools.", cr.System)
	require.Len(t, cr.Messages, 1)

	resp := `{
		"choices":[{"message":{"role":"assistant","content":null,"refusal":"I cannot help with that."},"finish_reason":"stop"}]
	}`
	cresp, err := a.DecodeResponse([]byte(resp))
	require.NoError(t, err)
	assert.Equal(t, "I cannot help with that.", cresp.Content)
}

// GPT-5 models accept freeform "custom" tools alongside classic "function"
// tools. A canonical round-trip must not turn one into the other (ENG-1281).
func TestCanonical_OpenAI_Completions_CustomToolRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		tool  string
		check func(t *testing.T, canonical CanonicalTool, encoded map[string]any)
	}{
		{
			name: "custom tool keeps its type, name and format",
			tool: `{"type":"custom","custom":{"name":"bash","description":"Run a shell command","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}}}`,
			check: func(t *testing.T, canonical CanonicalTool, encoded map[string]any) {
				assert.Equal(t, ToolKindCustom, canonical.Kind)
				assert.Equal(t, "bash", canonical.Name)
				assert.Equal(t, "Run a shell command", canonical.Description)

				assert.Equal(t, "custom", encoded["type"])
				assert.Nil(t, encoded["function"], "a custom tool must not be emitted as a function")

				custom, ok := encoded["custom"].(map[string]any)
				require.True(t, ok, "custom payload must survive: %v", encoded)
				assert.Equal(t, "bash", custom["name"])
				format, ok := custom["format"].(map[string]any)
				require.True(t, ok, "format must survive verbatim: %v", custom)
				assert.Equal(t, "lark", format["syntax"])
				assert.Equal(t, "start: /.+/", format["definition"])
			},
		},
		{
			name: "custom tool without a format stays a custom tool",
			tool: `{"type":"custom","custom":{"name":"freeform"}}`,
			check: func(t *testing.T, canonical CanonicalTool, encoded map[string]any) {
				assert.Equal(t, ToolKindCustom, canonical.Kind)
				assert.Equal(t, "freeform", canonical.Name)
				assert.Equal(t, "custom", encoded["type"])
				custom, ok := encoded["custom"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "freeform", custom["name"])
			},
		},
		{
			name: "function tool is unaffected",
			tool: `{"type":"function","function":{"name":"read_file","description":"Read","parameters":{"type":"object","properties":{"p":{"type":"string"}}}}}`,
			check: func(t *testing.T, canonical CanonicalTool, encoded map[string]any) {
				assert.Equal(t, ToolKindFunction, canonical.Kind)
				assert.Equal(t, "read_file", canonical.Name)
				assert.Equal(t, "function", encoded["type"])
				assert.Nil(t, encoded["custom"])
				fn, ok := encoded["function"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "read_file", fn["name"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := &OpenAIAdapter{}
			body := `{"model":"gpt-5.1","messages":[{"role":"user","content":"hi"}],"tools":[` + tc.tool + `]}`

			canonical, err := a.DecodeRequest([]byte(body))
			require.NoError(t, err)
			require.Len(t, canonical.Tools, 1)

			encoded, err := a.EncodeRequest(canonical)
			require.NoError(t, err)

			var out struct {
				Tools []map[string]any `json:"tools"`
			}
			require.NoError(t, json.Unmarshal(encoded, &out))
			require.Len(t, out.Tools, 1)

			tc.check(t, canonical.Tools[0], out.Tools[0])
		})
	}
}

// An agent loop replays previous custom tool calls in the message history, so
// the call shape must round-trip as faithfully as the tool declaration.
func TestCanonical_OpenAI_Completions_CustomToolCallRoundtrip(t *testing.T) {
	a := &OpenAIAdapter{}
	body := `{
		"model":"gpt-5.1",
		"messages":[
			{"role":"user","content":"run ls"},
			{"role":"assistant","tool_calls":[
				{"id":"call_1","type":"custom","custom":{"name":"bash","input":"ls -la /tmp"}},
				{"id":"call_2","type":"function","function":{"name":"read_file","arguments":"{\"p\":\"a.txt\"}"}}
			]},
			{"role":"tool","tool_call_id":"call_1","content":"total 0"}
		]
	}`

	cr, err := a.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 3)

	calls := cr.Messages[1].ToolCalls
	require.Len(t, calls, 2)
	assert.Equal(t, ToolKindCustom, calls[0].Kind)
	assert.Equal(t, "bash", calls[0].Name)
	assert.Equal(t, "ls -la /tmp", calls[0].Arguments, "freeform input is carried in Arguments")
	assert.Equal(t, ToolKindFunction, calls[1].Kind)
	assert.Equal(t, "read_file", calls[1].Name)

	encoded, err := a.EncodeRequest(cr)
	require.NoError(t, err)

	var out struct {
		Messages []struct {
			Role      string           `json:"role"`
			ToolCalls []map[string]any `json:"tool_calls"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(encoded, &out))

	var assistant []map[string]any
	for _, m := range out.Messages {
		if m.Role == "assistant" {
			assistant = m.ToolCalls
		}
	}
	require.Len(t, assistant, 2)

	assert.Equal(t, "custom", assistant[0]["type"])
	assert.Nil(t, assistant[0]["function"])
	custom, ok := assistant[0]["custom"].(map[string]any)
	require.True(t, ok, "custom call payload must survive: %v", assistant[0])
	assert.Equal(t, "bash", custom["name"])
	assert.Equal(t, "ls -la /tmp", custom["input"])

	assert.Equal(t, "function", assistant[1]["type"])
	assert.Nil(t, assistant[1]["custom"])
}

// Streamed custom tool calls put their freeform payload under "input" rather
// than "arguments"; re-encoding a chunk must not flatten them into an empty
// function call (ENG-1281).
func TestCanonical_OpenAI_Completions_CustomToolCallStreamRoundtrip(t *testing.T) {
	a := &OpenAIAdapter{}
	chunks := []string{
		`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"custom","custom":{"name":"bash"}}]}}]}`,
		`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"custom":{"input":"ls -la"}}]}}]}`,
	}

	var name, input string
	for _, raw := range chunks {
		sc, err := a.DecodeStreamChunk([]byte(raw))
		require.NoError(t, err)
		require.Len(t, sc.ToolCallDeltas, 1)
		delta := sc.ToolCallDeltas[0]
		assert.Equal(t, ToolKindCustom, delta.Kind)
		if delta.Name != "" {
			name = delta.Name
		}
		input += delta.ArgumentsDelta

		lines, err := a.EncodeStreamChunk(sc)
		require.NoError(t, err)
		require.NotEmpty(t, lines)

		payload := string(lines[0])
		assert.Contains(t, payload, `"type":"custom"`)
		assert.NotContains(t, payload, `"function"`, "a custom call must not be re-encoded as a function")
	}

	assert.Equal(t, "bash", name)
	assert.Equal(t, "ls -la", input)
}

// Tool-rewriting plugins re-encode the canonical request; a custom tool that
// survives the cycle must still be filterable by name.
func TestCanonical_OpenAI_Completions_CustomToolIsNamedForPlugins(t *testing.T) {
	a := &OpenAIAdapter{}
	body := `{"model":"gpt-5.1","messages":[{"role":"user","content":"hi"}],"tools":[
		{"type":"function","function":{"name":"read_file","parameters":{"type":"object"}}},
		{"type":"custom","custom":{"name":"bash","format":{"type":"text"}}}
	]}`

	canonical, err := a.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, canonical.Tools, 2)

	names := []string{canonical.Tools[0].Name, canonical.Tools[1].Name}
	assert.Equal(t, []string{"read_file", "bash"}, names)

	canonical.Tools = canonical.Tools[1:]
	encoded, err := a.EncodeRequest(canonical)
	require.NoError(t, err)

	var out struct {
		Tools []map[string]any `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(encoded, &out))
	require.Len(t, out.Tools, 1)
	assert.Equal(t, "custom", out.Tools[0]["type"])
}
