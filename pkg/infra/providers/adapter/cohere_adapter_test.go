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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCohereAdapter_RoundtripRequest(t *testing.T) {
	input := `{
		"model": "command-r-plus",
		"messages": [{"role": "user", "content": "Hello"}],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	a := &CohereAdapter{}
	canonical, err := a.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "command-r-plus", canonical.Model)
	assert.Len(t, canonical.Messages, 1)

	encoded, err := a.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "command-r-plus", result["model"])
}

func TestCohereAdapter_OpenAIToCohereCrossFormat(t *testing.T) {
	reg := NewRegistry()
	openaiReq := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`

	out, err := reg.AdaptRequest([]byte(openaiReq), FormatOpenAI, FormatCohere)
	require.NoError(t, err)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(out, &cohereReq))
	assert.Equal(t, "gpt-4", cohereReq["model"])
	msgs := cohereReq["messages"].([]any)
	assert.Len(t, msgs, 1)
}

func TestCohereAdapter_StreamChunkContentDelta(t *testing.T) {
	a := &CohereAdapter{}
	chunk := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"hi"}}}}`)

	got, err := a.DecodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "hi", got.Delta)
}

func TestUsageCache_Cohere_CachedTokens(t *testing.T) {
	const usage = `{"billed_units":{"input_tokens":1480,"output_tokens":12},"tokens":{"input_tokens":1500,"output_tokens":12},"cached_tokens":600}`
	want := &CanonicalUsage{InputTokens: 1500, OutputTokens: 12, TotalTokens: 1512, CachedInputTokens: 600}
	runUsageCases(t, &CohereAdapter{}, []usageCase{
		{
			name:      "buffered",
			body:      []byte(`{"id":"co-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":` + usage + `}`),
			path:      "response",
			wantUsage: want,
		},
		{
			name:      "stream message-end",
			body:      []byte(`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":` + usage + `}}`),
			path:      "stream",
			wantUsage: want,
		},
		{
			name:      "no cached tokens",
			body:      []byte(`{"id":"co-1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"hi"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":2}}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 10, OutputTokens: 2, TotalTokens: 12},
		},
	})
}

func TestCohereEmbedAdapter_OpenAIToCohere(t *testing.T) {
	reg := NewRegistry()
	openaiReq := `{"model":"embed-english-v3.0","input":["hello","world"]}`

	out, err := AdaptEmbeddingRequest(reg, []byte(openaiReq), FormatOpenAIEmbeddings, FormatCohereEmbed)
	require.NoError(t, err)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(out, &cohereReq))
	assert.Equal(t, "embed-english-v3.0", cohereReq["model"])
	assert.Equal(t, []any{"hello", "world"}, cohereReq["texts"])
}

func TestCohereRerankAdapter_DecodeRequest_Model(t *testing.T) {
	a := &CohereRerankAdapter{}
	body := []byte(`{"model":"rerank-english-v3.0","query":"q","documents":["a"]}`)

	got, err := a.DecodeRequest(body)
	require.NoError(t, err)
	assert.Equal(t, "rerank-english-v3.0", got.Model)
}

func TestCohere_DecodeStreamChunk_SkipsThinking(t *testing.T) {
	a := &CohereAdapter{}
	thinking := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"thinking","thinking":"private"}}}}`)
	chunk, err := a.DecodeStreamChunk(thinking)
	require.NoError(t, err)
	assert.Nil(t, chunk)

	text := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"hello"}}}}`)
	chunk, err = a.DecodeStreamChunk(text)
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, "hello", chunk.Delta)
}

const cohereToolCallStream = `event: message-start
data: {"id":"93b3f521-090e-4ebc-bac4-f7c557e63c00","type":"message-start","delta":{"message":{"role":"assistant","content":[],"tool_plan":"","tool_calls":[],"citations":[]}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":"Voy"}}}

event: tool-call-start
data: {"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"database_agent_3v76fs3zjrgq","type":"function","function":{"name":"database_agent","arguments":""}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{\n    \""}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"query"}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"\": \"Juan\""}}}}}

event: tool-call-delta
data: {"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"\n}"}}}}}

event: tool-call-end
data: {"type":"tool-call-end","index":0}

event: message-end
data: {"type":"message-end","delta":{"finish_reason":"TOOL_CALL","usage":{"billed_units":{"input_tokens":50,"output_tokens":26},"tokens":{"input_tokens":793,"output_tokens":61},"cached_tokens":176}}}

data: [DONE]
`

const cohereTextStream = `event: message-start
data: {"id":"5c1f","type":"message-start","delta":{"message":{"role":"assistant","content":[],"tool_plan":"","tool_calls":[],"citations":[]}}}

event: content-start
data: {"type":"content-start","index":0,"delta":{"message":{"content":{"type":"text","text":""}}}}

event: content-delta
data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":"Hola"}}}}

event: content-delta
data: {"type":"content-delta","index":0,"delta":{"message":{"content":{"text":" Juan"}}}}

event: content-end
data: {"type":"content-end","index":0}

event: message-end
data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":5,"output_tokens":2},"tokens":{"input_tokens":70,"output_tokens":2}}}}
`

func decodeCohereSSE(t *testing.T, stream string) []*CanonicalStreamChunk {
	t.Helper()
	a := &CohereAdapter{}
	var chunks []*CanonicalStreamChunk
	for line := range strings.SplitSeq(stream, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok || payload == "[DONE]" {
			continue
		}
		chunk, err := a.DecodeStreamChunk([]byte(payload))
		require.NoError(t, err)
		if chunk != nil {
			chunks = append(chunks, chunk)
		}
	}
	return chunks
}

func TestCohereAdapter_DecodeStreamToolCall(t *testing.T) {
	chunks := decodeCohereSSE(t, cohereToolCallStream)

	require.NotEmpty(t, chunks)
	assert.Equal(t, "assistant", chunks[0].Role)
	assert.Equal(t, "93b3f521-090e-4ebc-bac4-f7c557e63c00", chunks[0].ID)

	var id, name, args, plan string
	var finish string
	var usage *CanonicalUsage
	for _, c := range chunks {
		plan += c.Delta
		for _, tc := range c.ToolCallDeltas {
			assert.Equal(t, 0, tc.Index)
			if tc.ID != "" {
				id = tc.ID
			}
			if tc.Name != "" {
				name = tc.Name
			}
			args += tc.ArgumentsDelta
		}
		if c.FinishReason != "" {
			finish = c.FinishReason
		}
		usage = MergeUsage(usage, c.Usage)
	}
	assert.Equal(t, "database_agent_3v76fs3zjrgq", id)
	assert.Equal(t, "database_agent", name)
	assert.JSONEq(t, `{"query":"Juan"}`, args)
	assert.Equal(t, "Voy", plan, "the tool plan reaches other clients as text")
	assert.Equal(t, "tool_calls", finish)
	assert.Equal(t, &CanonicalUsage{InputTokens: 793, OutputTokens: 61, TotalTokens: 854, CachedInputTokens: 176}, usage)
}

func TestCohereAdapter_DecodeStreamToolPlan(t *testing.T) {
	chunks := decodeCohereSSE(t, `event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":"Voy"}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":" a"}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":" buscar"}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{"message":{"tool_plan":""}}}

event: tool-plan-delta
data: {"type":"tool-plan-delta","delta":{}}
`)

	require.Len(t, chunks, 3)
	var plan string
	for _, c := range chunks {
		assert.Empty(t, c.ToolCallDeltas)
		assert.Empty(t, c.FinishReason)
		plan += c.Delta
	}
	assert.Equal(t, "Voy a buscar", plan)
}

func TestCohereAdapter_DecodeStreamText(t *testing.T) {
	chunks := decodeCohereSSE(t, cohereTextStream)

	var text string
	for _, c := range chunks {
		text += c.Delta
	}
	assert.Equal(t, "Hola Juan", text)
	last := chunks[len(chunks)-1]
	assert.Equal(t, "stop", last.FinishReason)
	assert.Equal(t, &CanonicalUsage{InputTokens: 70, OutputTokens: 2, TotalTokens: 72}, last.Usage)
}

func TestCohereUsage_BilledUnitsOnly(t *testing.T) {
	chunk, err := (&CohereAdapter{}).DecodeStreamChunk([]byte(`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":9,"output_tokens":3}}}}`))
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, &CanonicalUsage{InputTokens: 9, OutputTokens: 3, TotalTokens: 12}, chunk.Usage)
}

func TestCohereUsage_BilledUnitsOnlyWithCacheCountsCachedAsInput(t *testing.T) {
	chunk, err := (&CohereAdapter{}).DecodeStreamChunk([]byte(`{"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"billed_units":{"input_tokens":50,"output_tokens":26},"cached_tokens":176}}}`))
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, &CanonicalUsage{InputTokens: 176, OutputTokens: 26, TotalTokens: 202, CachedInputTokens: 176}, chunk.Usage)
}

func TestCohereAdapter_EncodeResponseUsageShape(t *testing.T) {
	body, err := (&CohereAdapter{}).EncodeResponse(&CanonicalResponse{
		ID:           "gen-1",
		Content:      "hi",
		FinishReason: "stop",
		Usage:        &CanonicalUsage{InputTokens: 793, OutputTokens: 61, TotalTokens: 854, CachedInputTokens: 176},
	})
	require.NoError(t, err)

	var got struct {
		Usage json.RawMessage `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.JSONEq(t,
		`{"billed_units":{"input_tokens":793,"output_tokens":61},"tokens":{"input_tokens":793,"output_tokens":61},"cached_tokens":176}`,
		string(got.Usage))
}

func TestCohereAdapter_EncodeStreamChunkShapes(t *testing.T) {
	a := &CohereAdapter{}
	lines, err := a.EncodeStreamChunk(&CanonicalStreamChunk{
		ID:   "gen-1",
		Role: "assistant",
		ToolCallDeltas: []StreamToolCallDelta{
			{Index: 0, ID: "call_1", Name: "f"},
			{Index: 0, ArgumentsDelta: `{}`},
		},
	})
	require.NoError(t, err)

	var got []string
	for _, l := range lines {
		if p, ok := strings.CutPrefix(string(l), "data: "); ok {
			got = append(got, p)
		}
	}
	assert.Equal(t, []string{
		`{"id":"gen-1","type":"message-start","delta":{"message":{"role":"assistant"}}}`,
		`{"type":"tool-call-start","index":0,"delta":{"message":{"tool_calls":{"id":"call_1","type":"function","function":{"name":"f","arguments":""}}}}}`,
		`{"type":"tool-call-delta","index":0,"delta":{"message":{"tool_calls":{"function":{"arguments":"{}"}}}}}`,
	}, got)
}

func TestCohereAdapter_ToolPlan(t *testing.T) {
	a := &CohereAdapter{}

	t.Run("encode request sends assistant text with tool calls as the plan", func(t *testing.T) {
		body, err := a.EncodeRequest(&CanonicalRequest{Messages: []CanonicalMessage{
			{Role: "assistant", Content: "Voy", ToolCalls: []CanonicalToolCall{{ID: "call_1", Name: "f", Arguments: "{}"}}},
			{Role: "assistant", Content: "done"},
		}})
		require.NoError(t, err)
		var req struct {
			Messages []map[string]json.RawMessage `json:"messages"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		require.Len(t, req.Messages, 2)
		assert.JSONEq(t, `"Voy"`, string(req.Messages[0]["tool_plan"]))
		assert.NotContains(t, req.Messages[0], "content")
		assert.NotContains(t, req.Messages[1], "tool_plan")
		assert.JSONEq(t, `"done"`, string(req.Messages[1]["content"]))
	})

	t.Run("decode request reads the plan as assistant content", func(t *testing.T) {
		req, err := a.DecodeRequest([]byte(`{"messages":[{"role":"assistant","tool_plan":"Voy","tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]}]}`))
		require.NoError(t, err)
		require.Len(t, req.Messages, 1)
		assert.Equal(t, "Voy", req.Messages[0].Content)
		require.Len(t, req.Messages[0].ToolCalls, 1)
	})

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "decode response folds the plan into empty content",
			body: `{"id":"r","finish_reason":"TOOL_CALL","message":{"role":"assistant","tool_plan":"Voy","tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]}}`,
			want: "Voy",
		},
		{
			name: "decode response keeps content over the plan",
			body: `{"id":"r","finish_reason":"TOOL_CALL","message":{"role":"assistant","content":[{"type":"text","text":"hi"}],"tool_plan":"Voy"}}`,
			want: "hi",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := a.DecodeResponse([]byte(tt.body))
			require.NoError(t, err)
			assert.Equal(t, tt.want, resp.Content)
		})
	}
}

func TestCohereAdapter_EncodeResponseFinishReason(t *testing.T) {
	tests := []struct {
		finish string
		want   string
	}{
		{finish: "stop", want: "COMPLETE"},
		{finish: "length", want: "MAX_TOKENS"},
		{finish: "tool_calls", want: "TOOL_CALL"},
		{finish: "error", want: "ERROR"},
		{finish: "MALFORMED_FUNCTION_CALL", want: "ERROR"},
		{finish: "content_filter", want: "ERROR"},
		{finish: "refusal", want: "ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.finish, func(t *testing.T) {
			body, err := (&CohereAdapter{}).EncodeResponse(&CanonicalResponse{Content: "hi", FinishReason: tt.finish})
			require.NoError(t, err)
			var resp struct {
				FinishReason string `json:"finish_reason"`
			}
			require.NoError(t, json.Unmarshal(body, &resp))
			assert.Equal(t, tt.want, resp.FinishReason)
		})
	}
}

func TestCohereFinishToCanonical(t *testing.T) {
	tests := []struct {
		reason string
		want   string
	}{
		{reason: "COMPLETE", want: "stop"},
		{reason: "STOP_SEQUENCE", want: "stop"},
		{reason: "MAX_TOKENS", want: "length"},
		{reason: "TOOL_CALL", want: "tool_calls"},
		{reason: "ERROR", want: "error"},
		{reason: "ERROR_TOXIC", want: "content_filter"},
		{reason: "ERROR_LIMIT", want: "error"},
		{reason: "TIMEOUT", want: "error"},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			assert.Equal(t, tt.want, cohereFinishToCanonical(tt.reason))
		})
	}
}
