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

func TestUsageCache_OpenAIFamilyChat(t *testing.T) {
	const choice = `"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]`
	cases := []struct {
		name  string
		usage string
		want  *CanonicalUsage
		plain *int
	}{
		{
			name:  "deepseek hit reported twice counts once",
			usage: `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_cache_hit_tokens":80,"prompt_cache_miss_tokens":20,"prompt_tokens_details":{"cached_tokens":80}}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 5, TotalTokens: 105, CachedInputTokens: 80},
		},
		{
			name:  "deepseek hit without details",
			usage: `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_cache_hit_tokens":80,"prompt_cache_miss_tokens":20}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 5, TotalTokens: 105, CachedInputTokens: 80},
		},
		{
			name:  "deepseek prompt below hit plus miss",
			usage: `{"prompt_tokens":0,"completion_tokens":5,"total_tokens":0,"prompt_cache_hit_tokens":80,"prompt_cache_miss_tokens":20}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 5, TotalTokens: 105, CachedInputTokens: 80},
		},
		{
			name:  "cache write in details",
			usage: `{"prompt_tokens":2000,"completion_tokens":10,"total_tokens":2010,"prompt_tokens_details":{"cached_tokens":1000,"cache_write_tokens":500}}`,
			want:  &CanonicalUsage{InputTokens: 2000, OutputTokens: 10, TotalTokens: 2010, CachedInputTokens: 1000, CacheWriteInputTokens: 500},
		},
		{
			name:  "input kept as reported when read plus write exceeds it",
			usage: `{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80,"cache_write_tokens":40}}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 10, TotalTokens: 110, CachedInputTokens: 80, CacheWriteInputTokens: 40},
			plain: new(0),
		},
		{
			name:  "deepseek miss only",
			usage: `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_cache_hit_tokens":0,"prompt_cache_miss_tokens":100}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 5, TotalTokens: 105},
		},
		{
			name:  "deepseek miss only with total below input",
			usage: `{"prompt_tokens":0,"completion_tokens":5,"total_tokens":5,"prompt_cache_miss_tokens":100}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 5, TotalTokens: 105},
		},
		{
			name:  "deepseek hit with zero cached details",
			usage: `{"prompt_tokens":100,"completion_tokens":5,"total_tokens":105,"prompt_cache_hit_tokens":80,"prompt_cache_miss_tokens":20,"prompt_tokens_details":{"cached_tokens":0}}`,
			want:  &CanonicalUsage{InputTokens: 100, OutputTokens: 5, TotalTokens: 105, CachedInputTokens: 80},
		},
	}
	adapters := map[string]ProviderAdapter{"openai": &OpenAIAdapter{}, "openrouter": &OpenRouterAdapter{}}
	for adapterName, a := range adapters {
		for _, tc := range cases {
			t.Run(adapterName+"/"+tc.name+"/buffered", func(t *testing.T) {
				body := []byte(`{"id":"c1","object":"chat.completion","model":"m",` + choice + `,"usage":` + tc.usage + `}`)
				cr, err := a.DecodeResponse(body)
				require.NoError(t, err)
				assert.Equal(t, tc.want, cr.Usage)
				if tc.plain != nil {
					assert.Equal(t, *tc.plain, cr.Usage.PlainInputTokens())
				}
			})
			t.Run(adapterName+"/"+tc.name+"/stream", func(t *testing.T) {
				chunk := []byte(`{"id":"c1","object":"chat.completion.chunk","choices":[],"usage":` + tc.usage + `}`)
				sc, err := a.DecodeStreamChunk(chunk)
				require.NoError(t, err)
				require.NotNil(t, sc)
				assert.Equal(t, tc.want, sc.Usage)
				if tc.plain != nil {
					assert.Equal(t, *tc.plain, sc.Usage.PlainInputTokens())
				}
			})
		}
	}
}

func TestUsageCache_OpenAIChat_IncludeUsageChunkWrite(t *testing.T) {
	a := &OpenAIAdapter{}
	var merged *CanonicalUsage
	for _, chunk := range []string{
		`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}],"usage":null}`,
		`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}`,
		`{"id":"c1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":6000,"completion_tokens":20,"total_tokens":6020,"prompt_tokens_details":{"cached_tokens":0,"cache_write_tokens":500}}}`,
	} {
		sc, err := a.DecodeStreamChunk([]byte(chunk))
		require.NoError(t, err)
		if sc != nil {
			merged = MergeUsage(merged, sc.Usage)
		}
	}
	require.NotNil(t, merged)
	assert.Equal(t, &CanonicalUsage{InputTokens: 6000, OutputTokens: 20, TotalTokens: 6020, CacheWriteInputTokens: 500}, merged)
	assert.Equal(t, 5500, merged.PlainInputTokens())
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

func TestDecodeCompletionsStreamChunk_ReasoningOnly(t *testing.T) {
	t.Parallel()

	chunk := []byte(`{"id":"chatcmpl-1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"reasoning_content":"think"}}]}`)
	sc, err := (&OpenAIAdapter{}).DecodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotNil(t, sc)
	assert.Equal(t, "think", sc.ReasoningDelta)
	assert.Empty(t, sc.Delta)
}

func TestDecodeCompletionsStreamChunk_UpstreamError(t *testing.T) {
	tests := []struct {
		name       string
		chunk      string
		want       *UpstreamStreamError
		wantOnly   bool
		wantFinish string
		wantUsage  bool
	}{
		{
			name:     "error object",
			chunk:    `{"error":{"message":"The server had an error","type":"server_error","code":"internal"}}`,
			want:     &UpstreamStreamError{Type: "server_error", Code: "internal", Message: "The server had an error"},
			wantOnly: true,
		},
		{
			name:     "numeric code as OpenRouter sends it",
			chunk:    `{"id":"gen-1","object":"chat.completion.chunk","choices":[],"error":{"code":502,"message":"Provider returned error"}}`,
			want:     &UpstreamStreamError{Code: "502", Message: "Provider returned error"},
			wantOnly: true,
		},
		{
			name:     "string error",
			chunk:    `{"error":"overloaded"}`,
			want:     &UpstreamStreamError{Message: "overloaded"},
			wantOnly: true,
		},
		{
			name: "error with the failure finish and usage",
			chunk: `{"id":"gen-1","object":"chat.completion.chunk","error":{"code":502,"message":"Provider returned error"},` +
				`"choices":[{"index":0,"delta":{},"finish_reason":"error"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`,
			want:       &UpstreamStreamError{Code: "502", Message: "Provider returned error"},
			wantFinish: "error",
			wantUsage:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc, err := (&OpenAIAdapter{}).DecodeStreamChunk([]byte(tt.chunk))
			require.NoError(t, err)
			require.NotNil(t, sc)
			assert.Equal(t, tt.want, sc.UpstreamError)
			assert.Equal(t, tt.wantOnly, sc.UpstreamErrorOnly())
			assert.Equal(t, tt.wantFinish, sc.FinishReason)
			if tt.wantUsage {
				require.NotNil(t, sc.Usage)
				assert.Equal(t, 5, sc.Usage.InputTokens)
			}
		})
	}
}

func TestDecodeCompletionsStreamChunk_EmptyErrorIsAChunk(t *testing.T) {
	for _, raw := range []string{`null`, `""`, `{}`, `{"message":""}`, `{"message":"","code":null}`, `{"message":"","code":0}`, `{"type":"x","message":"","code":""}`, `false`, `0`} {
		t.Run(raw, func(t *testing.T) {
			chunk := `{"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hi"}}],"error":` + raw + `}`
			sc, err := (&OpenAIAdapter{}).DecodeStreamChunk([]byte(chunk))
			require.NoError(t, err)
			require.NotNil(t, sc)
			assert.Equal(t, "hi", sc.Delta)
			assert.Nil(t, sc.UpstreamError)
		})
	}
}

func TestFinishFailure(t *testing.T) {
	for _, reason := range []string{"error", "MALFORMED_FUNCTION_CALL", "UNEXPECTED_TOOL_CALL", "TOO_MANY_TOOL_CALLS"} {
		message, failed := FinishFailure(reason)
		assert.True(t, failed, reason)
		assert.NotEmpty(t, message, reason)
	}
	for _, reason := range []string{"", "stop", "length", "tool_calls", "OTHER", "LANGUAGE", "SAFETY"} {
		_, failed := FinishFailure(reason)
		assert.False(t, failed, reason)
	}
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

func TestEncodeCompletionsRequest_DropsNamelessTools(t *testing.T) {
	custom := func(name string) CanonicalTool {
		return CanonicalTool{Kind: ToolKindCustom, Name: name, Format: json.RawMessage(`{"type":"text"}`)}
	}
	tests := []struct {
		name           string
		tools          []CanonicalTool
		toolChoice     *CanonicalToolChoice
		wantNames      []string
		wantToolChoice bool
	}{
		{name: "nameless tool among named ones is dropped", tools: []CanonicalTool{{Name: "Read"}, {Name: ""}, {Name: "Write"}}, wantNames: []string{"Read", "Write"}},
		{name: "all nameless drops tools and tool_choice", tools: []CanonicalTool{{Name: ""}}, toolChoice: &CanonicalToolChoice{Type: "auto"}},
		{name: "named tool_choice to a kept tool survives", tools: []CanonicalTool{{Name: "Read"}, {Name: ""}}, toolChoice: &CanonicalToolChoice{Type: "tool", Name: "Read"}, wantNames: []string{"Read"}, wantToolChoice: true},
		{name: "named tool_choice to a dropped tool is omitted", tools: []CanonicalTool{{Name: "Read"}, {Name: ""}}, toolChoice: &CanonicalToolChoice{Type: "tool", Name: ""}, wantNames: []string{"Read"}},
		{name: "nothing dropped leaves an unknown tool_choice alone", tools: []CanonicalTool{{Name: "Read"}}, toolChoice: &CanonicalToolChoice{Type: "tool", Name: "Nope"}, wantNames: []string{"Read"}, wantToolChoice: true},
		{name: "whitespace-only name is blank", tools: []CanonicalTool{{Name: "  "}, {Name: "Read"}}, wantNames: []string{"Read"}},
		{name: "nameless custom tool is dropped", tools: []CanonicalTool{custom(""), custom("grep")}, wantNames: []string{"grep"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &CanonicalRequest{
				Model:      "gpt-5",
				Messages:   []CanonicalMessage{{Role: "user", Content: "hi"}},
				Tools:      tc.tools,
				ToolChoice: tc.toolChoice,
			}
			out, err := (&OpenAIAdapter{}).EncodeRequest(req)
			require.NoError(t, err)

			var got struct {
				Tools []struct {
					Function *struct{ Name string } `json:"function"`
					Custom   *struct{ Name string } `json:"custom"`
				} `json:"tools"`
				ToolChoice json.RawMessage `json:"tool_choice"`
			}
			require.NoError(t, json.Unmarshal(out, &got))

			var names []string
			for _, tool := range got.Tools {
				switch {
				case tool.Function != nil:
					names = append(names, tool.Function.Name)
				case tool.Custom != nil:
					names = append(names, tool.Custom.Name)
				}
			}
			assert.Equal(t, tc.wantNames, names)
			assert.Equal(t, tc.wantToolChoice, len(got.ToolChoice) > 0, "tool_choice presence")
		})
	}
}

func TestDecodeCompletionsRequest_Images(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		messages    string
		wantSystem  string
		wantContent string
		wantImages  []CanonicalImage
	}{
		{
			name:        "data uri",
			messages:    `[{"role":"user","content":[{"type":"text","text":"what is this?"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]`,
			wantContent: "what is this?",
			wantImages:  []CanonicalImage{{MediaType: "image/png", Data: "iVBORw0KGgo="}},
		},
		{
			name:        "url with detail",
			messages:    `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg","detail":"low"}}]}]`,
			wantContent: "",
			wantImages:  []CanonicalImage{{URL: "https://example.com/cat.jpg", Detail: "low"}},
		},
		{
			name:        "image_url as bare string",
			messages:    `[{"role":"user","content":[{"type":"image_url","image_url":"https://example.com/dog.png"}]}]`,
			wantContent: "",
			wantImages:  []CanonicalImage{{URL: "https://example.com/dog.png"}},
		},
		{
			name:        "malformed data uri kept as url",
			messages:    `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png,rawbytes"}}]}]`,
			wantContent: "",
			wantImages:  []CanonicalImage{{URL: "data:image/png,rawbytes"}},
		},
		{
			name:        "invalid detail keeps url",
			messages:    `[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/a.png","detail":5}}]}]`,
			wantContent: "",
			wantImages:  []CanonicalImage{{URL: "https://x/a.png"}},
		},
		{
			name:        "non-string url ignored",
			messages:    `[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":5}}]}]`,
			wantContent: "hi",
		},
		{
			name:        "image_url without url ignored",
			messages:    `[{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"detail":"low"}}]}]`,
			wantContent: "hi",
		},
		{
			name:        "image in system ignored",
			messages:    `[{"role":"system","content":[{"type":"text","text":"be brief"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]},{"role":"user","content":"hello"}]`,
			wantSystem:  "be brief",
			wantContent: "hello",
		},
		{
			name:        "several texts and an image",
			messages:    `[{"role":"user","content":[{"type":"text","text":"first"},{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,/9j/4AAQ"}},{"type":"text","text":"second"}]}]`,
			wantContent: "first\nsecond",
			wantImages:  []CanonicalImage{{MediaType: "image/jpeg", Data: "/9j/4AAQ"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := `{"model":"gpt-4o","messages":` + tt.messages + `}`
			canonical, err := (&OpenAIAdapter{}).DecodeRequest([]byte(body))
			require.NoError(t, err)

			assert.Equal(t, tt.wantSystem, canonical.System)
			require.Len(t, canonical.Messages, 1)
			assert.Equal(t, "user", canonical.Messages[0].Role)
			assert.Equal(t, tt.wantContent, canonical.Messages[0].Content)
			assert.Equal(t, tt.wantImages, canonical.Messages[0].Images)
		})
	}
}

func TestEncodeCompletionsRequest_Images(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		message     CanonicalMessage
		wantContent string
	}{
		{
			name: "images before text",
			message: CanonicalMessage{
				Role:    "user",
				Content: "compare them",
				Images: []CanonicalImage{
					{MediaType: "image/png", Data: "AAAA"},
					{URL: "https://example.com/cat.jpg", Detail: "high"},
				},
			},
			wantContent: `[
				{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},
				{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg","detail":"high"}},
				{"type":"text","text":"compare them"}
			]`,
		},
		{
			name: "image only has no text part",
			message: CanonicalMessage{
				Role:   "user",
				Images: []CanonicalImage{{MediaType: "image/webp", Data: "UklGR"}},
			},
			wantContent: `[{"type":"image_url","image_url":{"url":"data:image/webp;base64,UklGR"}}]`,
		},
		{
			name: "tool message with images keeps string content",
			message: CanonicalMessage{
				Role:       "tool",
				Content:    "result",
				ToolCallID: "call_1",
				Images:     []CanonicalImage{{MediaType: "image/png", Data: "AAAA"}},
			},
			wantContent: `"result"`,
		},
		{
			name: "assistant with tool calls and images keeps string content",
			message: CanonicalMessage{
				Role:      "assistant",
				Content:   "calling",
				ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "lookup", Arguments: "{}"}},
				Images:    []CanonicalImage{{MediaType: "image/png", Data: "AAAA"}},
			},
			wantContent: `"calling"`,
		},
		{
			name: "plain assistant with images keeps string content",
			message: CanonicalMessage{
				Role:    "assistant",
				Content: "sure",
				Images:  []CanonicalImage{{MediaType: "image/png", Data: "AAAA"}},
			},
			wantContent: `"sure"`,
		},
		{
			name:        "no images keeps string content",
			message:     CanonicalMessage{Role: "user", Content: "hello"},
			wantContent: `"hello"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := (&OpenAIAdapter{}).EncodeRequest(&CanonicalRequest{
				Model:    "gpt-4o",
				Messages: []CanonicalMessage{tt.message},
			})
			require.NoError(t, err)

			var out struct {
				Messages []struct {
					Content json.RawMessage `json:"content"`
				} `json:"messages"`
			}
			require.NoError(t, json.Unmarshal(encoded, &out))
			require.Len(t, out.Messages, 1)
			assert.JSONEq(t, tt.wantContent, string(out.Messages[0].Content))
		})
	}
}

func TestCompletionsRequest_PluginRewriteKeepsImage(t *testing.T) {
	t.Parallel()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":[
		{"type":"text","text":"my email is a@b.c"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA","detail":"low"}}
	]}]}`

	a := &OpenAIAdapter{}
	canonical, err := a.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, canonical.Messages, 1)

	canonical.Messages[0].Content = "my email is [REDACTED]"

	encoded, err := a.EncodeRequest(canonical)
	require.NoError(t, err)

	var out struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(encoded, &out))
	require.Len(t, out.Messages, 1)
	assert.JSONEq(t, `[
		{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA","detail":"low"}},
		{"type":"text","text":"my email is [REDACTED]"}
	]`, string(out.Messages[0].Content))
	assert.NotContains(t, string(encoded), "a@b.c")
}
