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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireAnthropicRequestDecodeError(
	t *testing.T,
	err error,
	secrets ...string,
) *RequestDecodeError {
	t.Helper()
	var decodeError *RequestDecodeError
	require.ErrorAs(t, err, &decodeError)
	require.Equal(t, FormatAnthropic, decodeError.Format)
	require.EqualError(
		t,
		decodeError,
		`invalid request body for format "anthropic": the payload could not be parsed as a valid anthropic API request`,
	)
	for current := err; current != nil; current = errors.Unwrap(current) {
		for _, secret := range secrets {
			assert.NotContains(t, current.Error(), secret)
		}
	}
	return decodeError
}

// ---------------------------------------------------------------------------
// Canonical roundtrip: Anthropic → Canonical → Anthropic
// ---------------------------------------------------------------------------

func TestCanonical_Anthropic_Roundtrip(t *testing.T) {
	input := `{
		"model": "claude-3-sonnet",
		"system": "You are helpful.",
		"messages": [
			{"role": "user", "content": "Hello"}
		],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	adapter := &AnthropicAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "claude-3-sonnet", canonical.Model)
	assert.Equal(t, "You are helpful.", canonical.System)
	assert.Len(t, canonical.Messages, 1)
	assert.Equal(t, 100, canonical.MaxTokens)

	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "You are helpful.", result["system"])
	msgs := result["messages"].([]interface{})
	assert.Len(t, msgs, 1)
}

func TestAnthropicDecodeRequest_SystemRepresentations(t *testing.T) {
	tests := []struct {
		name       string
		system     string
		wantSystem string
	}{
		{
			name:       "string remains exact",
			system:     `"  Keep exact bytes.\nNext line.  "`,
			wantSystem: "  Keep exact bytes.\nNext line.  ",
		},
		{
			name: "ordered text blocks",
			system: `[
				{"type":"text","text":"First"},
				{"type":"text","text":"Second"}
			]`,
			wantSystem: "First\nSecond",
		},
		{
			name: "next block supplies merge boundary",
			system: `[
				{"type":"text","text":"Base"},
				{"type":"text","text":"\n\nDecorated"}
			]`,
			wantSystem: "Base\n\nDecorated",
		},
		{
			name: "blank blocks are omitted",
			system: `[
				{"type":"text","text":"First"},
				{"type":"text","text":" \n\t "},
				{"type":"text","text":"Second"}
			]`,
			wantSystem: "First\nSecond",
		},
		{
			name: "all-whitespace blocks produce empty canonical system",
			system: `[
				{"type":"text","text":" "},
				{"type":"text","text":"\n\t"}
			]`,
			wantSystem: "",
		},
		{
			name: "plugin-produced text block extensions are permitted",
			system: `[
				{"type":"text","text":"Cached","cache_control":{"type":"ephemeral"}},
				{"type":"text","text":"Decorated","future_field":true}
			]`,
			wantSystem: "Cached\nDecorated",
		},
	}

	adapter := &AnthropicAdapter{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"model":"claude","system":` + test.system + `,"messages":[{"role":"user","content":"User message"}],"max_tokens":64}`)
			original := append([]byte(nil), body...)

			canonical, err := adapter.DecodeRequest(body)

			require.NoError(t, err)
			assert.Equal(t, test.wantSystem, canonical.System)
			require.Len(t, canonical.Messages, 1)
			assert.Equal(t, "user", canonical.Messages[0].Role)
			assert.Equal(t, "User message", canonical.Messages[0].Content)
			assert.Equal(t, original, body)
		})
	}
}

func TestAnthropicDecodeRequest_InvalidSystemArrays(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCause string
	}{
		{
			name:      "system is object",
			body:      `{"system":{"type":"text","text":"secret"},"messages":[],"max_tokens":64}`,
			wantCause: "anthropic system must be a string or an array of text blocks",
		},
		{
			name:      "block is not object",
			body:      `{"system":["secret"],"messages":[],"max_tokens":64}`,
			wantCause: "anthropic system block 0 must be a JSON object",
		},
		{
			name:      "missing block type",
			body:      `{"system":[{"text":"secret"}],"messages":[],"max_tokens":64}`,
			wantCause: "anthropic system block 0 must contain a string type",
		},
		{
			name:      "unsupported block type",
			body:      `{"system":[{"type":"image","text":"secret"}],"messages":[],"max_tokens":64}`,
			wantCause: "anthropic system block 0 has unsupported type",
		},
		{
			name:      "block type is strict lowercase",
			body:      `{"system":[{"type":"Text","text":"secret"}],"messages":[],"max_tokens":64}`,
			wantCause: "anthropic system block 0 has unsupported type",
		},
		{
			name:      "non-string block text",
			body:      `{"system":[{"type":"text","text":{"value":"secret"}}],"messages":[],"max_tokens":64}`,
			wantCause: "anthropic system block 0 must contain string text",
		},
		{
			name:      "duplicate block type",
			body:      `{"system":[{"type":"text","type":"text","text":"secret"}],"messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains duplicate field "type"`,
		},
		{
			name:      "duplicate block text",
			body:      `{"system":[{"type":"text","text":"secret","text":"other"}],"messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains duplicate field "text"`,
		},
		{
			name:      "block type alias",
			body:      `{"system":[{"Type":"text","text":"secret"}],"messages":[],"max_tokens":64}`,
			wantCause: `anthropic system block 0 contains invalid field alias "Type"`,
		},
		{
			name:      "block text mixed-case duplicate",
			body:      `{"system":[{"type":"text","text":"secret","Text":"other"}],"messages":[],"max_tokens":64}`,
			wantCause: `anthropic system block 0 contains invalid field alias "Text"`,
		},
		{
			name:      "duplicate top-level system",
			body:      `{"system":"secret","system":[{"type":"text","text":"other"}],"messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains duplicate field "system"`,
		},
		{
			name:      "duplicate top-level messages",
			body:      `{"system":"secret","messages":[],"messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains duplicate field "messages"`,
		},
		{
			name:      "top-level system alias",
			body:      `{"System":"secret","messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains invalid field alias "System"`,
		},
		{
			name:      "top-level system mixed-case duplicate",
			body:      `{"system":"secret","sYsTeM":"other","messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains invalid field alias "sYsTeM"`,
		},
		{
			name:      "top-level messages mixed-case duplicate",
			body:      `{"system":"secret","messages":[],"Messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains invalid field alias "Messages"`,
		},
		{
			name:      "top-level model alias",
			body:      `{"Model":"secret","messages":[],"max_tokens":64}`,
			wantCause: `anthropic request contains invalid field alias "Model"`,
		},
	}

	adapter := &AnthropicAdapter{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := adapter.DecodeRequest([]byte(test.body))

			decodeError := requireAnthropicRequestDecodeError(t, err, "secret", "other")
			require.EqualError(t, errors.Unwrap(decodeError), test.wantCause)
		})
	}
}

func TestAnthropicDecodeRequest_FailuresUseSanitizedTypedPath(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCause string
		run       func([]byte) error
	}{
		{
			name:      "syntax",
			body:      `{"system":"private prompt","messages":[`,
			wantCause: "decode anthropic request JSON",
			run: func(body []byte) error {
				_, err := testRegistry().DecodeRequestFor(body, FormatAnthropic)
				return err
			},
		},
		{
			name:      "type",
			body:      `{"system":"private prompt","messages":"private messages"}`,
			wantCause: `anthropic request field "messages" has invalid type`,
			run: func(body []byte) error {
				_, err := testRegistry().DecodeRequestFor(body, FormatAnthropic)
				return err
			},
		},
		{
			name:      "semantic through adaptation",
			body:      `{"system":[{"type":"image","text":"private prompt"}],"messages":[]}`,
			wantCause: "anthropic system block 0 has unsupported type",
			run: func(body []byte) error {
				_, err := testRegistry().AdaptRequest(body, FormatAnthropic, FormatOpenAI)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run([]byte(test.body))

			decodeError := requireAnthropicRequestDecodeError(t, err, "private prompt", "private messages")
			require.EqualError(t, errors.Unwrap(decodeError), test.wantCause)
		})
	}
}

func TestAnthropicDecodeRequest_StrictMessagesPreserveRichContent(t *testing.T) {
	body := []byte(`{
		"model":"claude",
		"messages":[
			{
				"role":"user",
				"content":[{"type":"text","text":"Question","cache_control":{"type":"ephemeral"},"future_field":true}],
				"message_extension":{"enabled":true}
			},
			{
				"role":"assistant",
				"content":[
					{"type":"text","text":"Answer","future_field":true},
					{"type":"tool_use","id":"tool_1","name":"lookup","input":{"query":"value"},"future_field":true}
				]
			}
		],
		"max_tokens":64
	}`)

	canonical, err := (&AnthropicAdapter{}).DecodeRequest(body)

	require.NoError(t, err)
	require.Len(t, canonical.Messages, 2)
	assert.Equal(t, "user", canonical.Messages[0].Role)
	assert.Equal(t, "Question", canonical.Messages[0].Content)
	assert.Equal(t, "assistant", canonical.Messages[1].Role)
	assert.Equal(t, "Answer", canonical.Messages[1].Content)
	require.Len(t, canonical.Messages[1].ToolCalls, 1)
	assert.Equal(t, "tool_1", canonical.Messages[1].ToolCalls[0].ID)
	assert.Equal(t, "lookup", canonical.Messages[1].ToolCalls[0].Name)
	assert.JSONEq(t, `{"query":"value"}`, canonical.Messages[1].ToolCalls[0].Arguments)
}

func TestAnthropicDecodeRequest_PreservesProtocolLikeKeysInsideUserObjects(t *testing.T) {
	body := []byte(`{
		"model":"claude",
		"system":[{"type":"text","text":"Rules","cache_control":{"Type":"ephemeral","Content":{"Messages":[],"System":"cache"}}}],
		"metadata":{"Role":"audit","Type":"trace","Content":{"Messages":[],"System":"metadata"}},
		"tools":[{
			"name":"lookup",
			"input_schema":{
				"type":"object",
				"properties":{
					"Role":{"Type":"string"},
					"Content":{"Messages":[],"System":"schema"}
				}
			}
		}],
		"messages":[{
			"role":"assistant",
			"content":[
				{"type":"text","text":"Answer","extension":{"Role":"viewer","Type":"custom","Content":{"Messages":[],"System":"block"}}},
				{"type":"tool_use","id":"tool_1","name":"lookup","input":{"Role":"operator","Type":"query","Content":{"Messages":[],"System":"argument"}}}
			],
			"message_extension":{"Role":"assistant-data","Type":"message","Content":{"Messages":[],"System":"extension"}}
		}],
		"max_tokens":64
	}`)

	canonical, err := (&AnthropicAdapter{}).DecodeRequest(body)

	require.NoError(t, err)
	require.Equal(t, "Rules", canonical.System)
	metadata, err := json.Marshal(canonical.Metadata)
	require.NoError(t, err)
	require.JSONEq(t, `{"Role":"audit","Type":"trace","Content":{"Messages":[],"System":"metadata"}}`, string(metadata))
	require.Len(t, canonical.Tools, 1)
	schema, err := json.Marshal(canonical.Tools[0].Schema)
	require.NoError(t, err)
	require.JSONEq(
		t,
		`{"type":"object","properties":{"Role":{"Type":"string"},"Content":{"Messages":[],"System":"schema"}}}`,
		string(schema),
	)
	require.Len(t, canonical.Messages, 1)
	require.Equal(t, "Answer", canonical.Messages[0].Content)
	require.Len(t, canonical.Messages[0].ToolCalls, 1)
	require.JSONEq(
		t,
		`{"Role":"operator","Type":"query","Content":{"Messages":[],"System":"argument"}}`,
		canonical.Messages[0].ToolCalls[0].Arguments,
	)
}

func TestAnthropicDecodeRequest_RejectsAllExactObjectDuplicates(t *testing.T) {
	tests := map[string]string{
		"untouched top-level field": `{"future":"private prompt","future":"other","messages":[]}`,
		"untouched message field":   `{"messages":[{"role":"user","content":"hello","future":"private prompt","future":"other"}]}`,
		"nested content extension":  `{"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache":{"ttl":"private prompt","ttl":"other"}}]}]}`,
		"nested tool input":         `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"1","name":"lookup","input":{"query":"private prompt","query":"other"}}]}]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := (&AnthropicAdapter{}).DecodeRequest([]byte(body))

			decodeError := requireAnthropicRequestDecodeError(t, err, "private prompt", "other")
			require.Contains(t, errors.Unwrap(decodeError).Error(), "duplicate field")
		})
	}
}

func TestAnthropicDecodeRequest_RejectsInvalidMessageEnvelopes(t *testing.T) {
	tests := []struct {
		name      string
		message   string
		wantCause string
	}{
		{
			name:      "message is not object",
			message:   `"private prompt"`,
			wantCause: "anthropic message 0 must be a JSON object",
		},
		{
			name:      "duplicate role",
			message:   `{"role":"user","role":"assistant","content":"private prompt"}`,
			wantCause: `anthropic request contains duplicate field "role"`,
		},
		{
			name:      "duplicate content",
			message:   `{"role":"user","content":"private prompt","content":"other"}`,
			wantCause: `anthropic request contains duplicate field "content"`,
		},
		{
			name:      "role alias",
			message:   `{"Role":"user","content":"private prompt"}`,
			wantCause: `anthropic message 0 contains invalid field alias "Role"`,
		},
		{
			name:      "content mixed-case duplicate",
			message:   `{"role":"user","content":"private prompt","Content":"other"}`,
			wantCause: `anthropic message 0 contains invalid field alias "Content"`,
		},
		{
			name:      "content block type alias",
			message:   `{"role":"user","content":[{"Type":"text","text":"private prompt"}]}`,
			wantCause: `anthropic message 0 content block 0 contains invalid field alias "Type"`,
		},
		{
			name:      "content block text alias",
			message:   `{"role":"user","content":[{"type":"text","Text":"private prompt"}]}`,
			wantCause: `anthropic message 0 content block 0 contains invalid field alias "Text"`,
		},
		{
			name:      "missing role",
			message:   `{"content":"private prompt"}`,
			wantCause: "anthropic message 0 must contain a string role",
		},
		{
			name:      "invalid role type",
			message:   `{"role":{"value":"user"},"content":"private prompt"}`,
			wantCause: "anthropic message 0 must contain a string role",
		},
		{
			name:      "nested system",
			message:   `{"role":"system","content":"private prompt"}`,
			wantCause: "anthropic message 0 has unsupported role",
		},
		{
			name:      "nested tool",
			message:   `{"role":"tool","content":"private prompt"}`,
			wantCause: "anthropic message 0 has unsupported role",
		},
		{
			name:      "wrong-case user",
			message:   `{"role":"User","content":"private prompt"}`,
			wantCause: "anthropic message 0 has unsupported role",
		},
		{
			name:      "wrong-case assistant",
			message:   `{"role":"Assistant","content":"private prompt"}`,
			wantCause: "anthropic message 0 has unsupported role",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"messages":[` + test.message + `],"max_tokens":64}`)

			_, err := (&AnthropicAdapter{}).DecodeRequest(body)

			decodeError := requireAnthropicRequestDecodeError(t, err, "private prompt", "other")
			require.EqualError(t, errors.Unwrap(decodeError), test.wantCause)
		})
	}
}

func TestAnthropicAdaptRequest_RejectsNestedSystemAuthority(t *testing.T) {
	body := []byte(`{
		"model":"anthropic.claude-3-5-sonnet-20241022-v2:0",
		"messages":[{"role":"system","content":"private authority"}],
		"max_tokens":64
	}`)

	for _, target := range []Format{FormatOpenAI, FormatBedrock} {
		t.Run(string(target), func(t *testing.T) {
			output, err := testRegistry().AdaptRequest(body, FormatAnthropic, target)

			assert.Nil(t, output)
			decodeError := requireAnthropicRequestDecodeError(t, err, "private authority")
			require.Equal(t, FormatAnthropic, decodeError.Format)
			require.EqualError(t, errors.Unwrap(decodeError), "anthropic message 0 has unsupported role")
		})
	}
}

// ---------------------------------------------------------------------------
// Real Anthropic request with stream + tools
// ---------------------------------------------------------------------------

func TestCanonical_Anthropic_RealRequest_WithStreamAndTools(t *testing.T) {
	input := `{
		"max_tokens": 64000,
		"messages": [{"role": "user", "content": "buscame en la base de datos el cliente Juan"}],
		"model": "claude-sonnet-4-20250514",
		"stream": true,
		"system": "You are an orchestrator.",
		"tools": [
			{
				"name": "database_agent",
				"input_schema": {
					"properties": {"query": {"type": "string"}},
					"required": ["query"],
					"type": "object"
				},
				"description": "Query the Postgres database."
			}
		]
	}`

	adapter := &AnthropicAdapter{}

	canonical, err := adapter.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "claude-sonnet-4-20250514", canonical.Model)
	assert.Equal(t, "You are an orchestrator.", canonical.System)
	assert.True(t, canonical.Stream, "stream should be true")
	assert.Equal(t, 64000, canonical.MaxTokens)
	assert.Len(t, canonical.Messages, 1)
	assert.Equal(t, "buscame en la base de datos el cliente Juan", canonical.Messages[0].Content)
	assert.Len(t, canonical.Tools, 1)
	assert.Equal(t, "database_agent", canonical.Tools[0].Name)

	// Roundtrip: encode back to Anthropic
	encoded, err := adapter.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(encoded, &result))

	assert.Equal(t, "claude-sonnet-4-20250514", result["model"])
	assert.Equal(t, "You are an orchestrator.", result["system"])
	assert.Equal(t, true, result["stream"])
	assert.Equal(t, float64(64000), result["max_tokens"])

	// Cross-provider: Anthropic → OpenAI (should preserve stream)
	openaiBody, err := testRegistry().AdaptRequest([]byte(input), FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, true, openaiResult["stream"])
	msgs := openaiResult["messages"].([]interface{})
	assert.Len(t, msgs, 2) // system re-injected + user
	tools := openaiResult["tools"].([]interface{})
	assert.Len(t, tools, 1)
	tool := tools[0].(map[string]interface{})
	assert.Equal(t, "function", tool["type"])
}

// ---------------------------------------------------------------------------
// Anthropic tool_use response: real-world payload
// ---------------------------------------------------------------------------

func TestAnthropic_DecodeResponse_ToolUse_RealPayload(t *testing.T) {
	// Exact payload from Anthropic Claude.
	body := `{
		"model": "claude-sonnet-4-20250514",
		"id": "msg_015uW5QLWaDeLdqegC29faCw",
		"type": "message",
		"role": "assistant",
		"content": [{
			"type": "tool_use",
			"id": "toolu_016u41qZE8fBygCBmSxapu7x",
			"name": "database_agent",
			"input": {
				"query": "Buscar cliente con nombre Juan"
			}
		}],
		"stop_reason": "tool_use",
		"stop_sequence": null,
		"usage": {
			"input_tokens": 1030,
			"cache_creation_input_tokens": 0,
			"cache_read_input_tokens": 0,
			"cache_creation": {
				"ephemeral_5m_input_tokens": 0,
				"ephemeral_1h_input_tokens": 0
			},
			"output_tokens": 86,
			"service_tier": "standard",
			"inference_geo": "not_available"
		}
	}`

	adapter := &AnthropicAdapter{}

	// Decode to canonical
	cr, err := adapter.DecodeResponse([]byte(body))
	require.NoError(t, err)

	// ID, Model, Role
	assert.Equal(t, "msg_015uW5QLWaDeLdqegC29faCw", cr.ID)
	assert.Equal(t, "claude-sonnet-4-20250514", cr.Model)
	assert.Equal(t, "assistant", cr.Role)

	// Content should be empty (no text blocks)
	assert.Equal(t, "", cr.Content)

	// Tool calls
	require.Len(t, cr.ToolCalls, 1)
	assert.Equal(t, "toolu_016u41qZE8fBygCBmSxapu7x", cr.ToolCalls[0].ID)
	assert.Equal(t, "database_agent", cr.ToolCalls[0].Name)
	assert.Contains(t, cr.ToolCalls[0].Arguments, "Buscar cliente con nombre Juan")

	// FinishReason: tool_use → tool_calls
	assert.Equal(t, "tool_calls", cr.FinishReason)

	// Usage — core tokens
	require.NotNil(t, cr.Usage)
	assert.Equal(t, 1030, cr.Usage.InputTokens)
	assert.Equal(t, 86, cr.Usage.OutputTokens)
	assert.Equal(t, 1116, cr.Usage.TotalTokens)

	// Usage — cache/billing pass-through
	assert.Equal(t, 0, cr.Usage.CacheCreationInputTokens)
	assert.Equal(t, 0, cr.Usage.CacheReadInputTokens)
	assert.Equal(t, "standard", cr.Usage.ServiceTier)

	// Roundtrip: canonical → Anthropic → canonical
	encoded, err := adapter.EncodeResponse(cr)
	require.NoError(t, err)

	cr2, err := adapter.DecodeResponse(encoded)
	require.NoError(t, err)

	assert.Equal(t, cr.ID, cr2.ID)
	assert.Equal(t, cr.Model, cr2.Model)
	assert.Equal(t, cr.FinishReason, cr2.FinishReason)
	require.Len(t, cr2.ToolCalls, 1)
	assert.Equal(t, cr.ToolCalls[0].ID, cr2.ToolCalls[0].ID)
	assert.Equal(t, cr.ToolCalls[0].Name, cr2.ToolCalls[0].Name)
	assert.Equal(t, cr.Usage.ServiceTier, cr2.Usage.ServiceTier)
	assert.Equal(t, cr.Usage.CacheCreationInputTokens, cr2.Usage.CacheCreationInputTokens)
	assert.Equal(t, cr.Usage.CacheReadInputTokens, cr2.Usage.CacheReadInputTokens)

	// Cross-format: canonical → OpenAI
	openaiAdapter := &OpenAIAdapter{}
	openaiBody, err := openaiAdapter.EncodeResponse(cr)
	require.NoError(t, err)

	var openaiResult map[string]interface{}
	require.NoError(t, json.Unmarshal(openaiBody, &openaiResult))

	assert.Equal(t, "chat.completion", openaiResult["object"])
	choices := openaiResult["choices"].([]interface{})
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]interface{})
	assert.Equal(t, "tool_calls", choice["finish_reason"])
	msg := choice["message"].(map[string]interface{})
	toolCalls := msg["tool_calls"].([]interface{})
	require.Len(t, toolCalls, 1)
	tc := toolCalls[0].(map[string]interface{})
	assert.Equal(t, "function", tc["type"])
	fn := tc["function"].(map[string]interface{})
	assert.Equal(t, "database_agent", fn["name"])
}

func TestUsageExtraction_Anthropic(t *testing.T) {
	runUsageCases(t, &AnthropicAdapter{}, []usageCase{
		{
			name:      "response with usage",
			body:      []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":30,"output_tokens":15}}`),
			path:      "response",
			wantUsage: &CanonicalUsage{InputTokens: 30, OutputTokens: 15, TotalTokens: 45},
		},
		{
			name:      "response no usage",
			body:      []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn"}`),
			path:      "response",
			wantUsage: nil,
		},
		{
			// Anthropic emits both cumulative input_tokens and output_tokens
			// on message_delta, so a single decode reconstructs the totals.
			name:      "stream message_delta with usage",
			body:      []byte(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":10,"output_tokens":20}}`),
			path:      "stream",
			wantUsage: &CanonicalUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30},
		},
		{
			name:      "stream content_block_delta no usage",
			body:      []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`),
			path:      "stream",
			wantUsage: nil,
		},
	})
}

func TestAnthropicSSE_CacheFieldRoundTrip_MessageDelta(t *testing.T) {
	adapter := &AnthropicAdapter{}
	chunk := &CanonicalStreamChunk{
		FinishReason: "stop",
		Usage: &CanonicalUsage{
			InputTokens:              1,
			OutputTokens:             1,
			TotalTokens:              2,
			CacheCreationInputTokens: 4,
			CacheReadInputTokens:     9,
		},
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	var decoded *CanonicalStreamChunk
	for _, line := range lines {
		payload := bytes.TrimPrefix(line, []byte("data: "))
		if len(payload) == len(line) {
			continue
		}
		if !bytes.Contains(payload, []byte("message_delta")) {
			continue
		}
		decoded, err = adapter.DecodeStreamChunk(payload)
		require.NoError(t, err)
		break
	}
	require.NotNil(t, decoded, "message_delta event must round-trip")
	require.NotNil(t, decoded.Usage)
	assert.Equal(t, 4, decoded.Usage.CacheCreationInputTokens)
	assert.Equal(t, 9, decoded.Usage.CacheReadInputTokens)
}

func TestAnthropicSSE_CacheFieldRoundTrip_MessageStart(t *testing.T) {
	adapter := &AnthropicAdapter{}
	chunk := &CanonicalStreamChunk{
		ID:    "msg_round_trip",
		Model: "claude-3-sonnet",
		Role:  "assistant",
		Usage: &CanonicalUsage{
			InputTokens:              1,
			OutputTokens:             1,
			TotalTokens:              2,
			CacheCreationInputTokens: 4,
			CacheReadInputTokens:     9,
		},
	}

	lines, err := adapter.EncodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotEmpty(t, lines)

	var decoded *CanonicalStreamChunk
	for _, line := range lines {
		payload := bytes.TrimPrefix(line, []byte("data: "))
		if len(payload) == len(line) {
			continue
		}
		if !bytes.Contains(payload, []byte(`"type":"message_start"`)) {
			continue
		}
		decoded, err = adapter.DecodeStreamChunk(payload)
		require.NoError(t, err)
		break
	}
	require.NotNil(t, decoded, "message_start event must round-trip")
	require.NotNil(t, decoded.Usage)
	assert.Equal(t, 4, decoded.Usage.CacheCreationInputTokens)
	assert.Equal(t, 9, decoded.Usage.CacheReadInputTokens)
}
