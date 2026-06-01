package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NormalizeOpenAIRequest
// ---------------------------------------------------------------------------

func TestNormalizeOpenAIRequest_InjectsTypeFunctionWhenMissing(t *testing.T) {
	// Simulates what the Mistral SDK sends: tool_calls without "type"
	input := `{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"tool_calls": [
					{"id": "abc123xyz", "function": {"name": "search", "arguments": "{\"q\":\"test\"}"}}
				]
			},
			{"role": "tool", "tool_call_id": "abc123xyz", "content": "result"}
		]
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["messages"], &msgs))

	// Assistant message (index 1) should have tool_calls with type
	var tcs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msgs[1]["tool_calls"], &tcs))
	require.Len(t, tcs, 1)

	var tcType string
	require.NoError(t, json.Unmarshal(tcs[0]["type"], &tcType))
	assert.Equal(t, "function", tcType)
}

func TestNormalizeOpenAIRequest_PreservesExistingType(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{
				"role": "assistant",
				"tool_calls": [
					{"id": "abc", "type": "function", "function": {"name": "search", "arguments": "{}"}}
				]
			}
		]
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["messages"], &msgs))

	var tcs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msgs[0]["tool_calls"], &tcs))

	var tcType string
	require.NoError(t, json.Unmarshal(tcs[0]["type"], &tcType))
	assert.Equal(t, "function", tcType)
}

func TestNormalizeOpenAIRequest_NoOpWhenNoToolCalls(t *testing.T) {
	input := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	out := NormalizeOpenAIRequest([]byte(input))
	assert.JSONEq(t, input, string(out))
}

func TestNormalizeOpenAIRequest_NoOpWhenNoMessages(t *testing.T) {
	input := `{"model":"gpt-4"}`
	out := NormalizeOpenAIRequest([]byte(input))
	assert.JSONEq(t, input, string(out))
}

func TestNormalizeOpenAIRequest_HandlesInvalidJSON(t *testing.T) {
	input := `not json at all`
	out := NormalizeOpenAIRequest([]byte(input))
	assert.Equal(t, input, string(out), "invalid JSON should return original body")
}

func TestNormalizeOpenAIRequest_HandlesNullType(t *testing.T) {
	input := `{
		"messages": [
			{
				"role": "assistant",
				"tool_calls": [
					{"id": "abc", "type": null, "function": {"name": "search", "arguments": "{}"}}
				]
			}
		]
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["messages"], &msgs))

	var tcs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msgs[0]["tool_calls"], &tcs))

	var tcType string
	require.NoError(t, json.Unmarshal(tcs[0]["type"], &tcType))
	assert.Equal(t, "function", tcType)
}

func TestNormalizeOpenAIRequest_HandlesEmptyStringType(t *testing.T) {
	input := `{
		"messages": [
			{
				"role": "assistant",
				"tool_calls": [
					{"id": "abc", "type": "", "function": {"name": "search", "arguments": "{}"}}
				]
			}
		]
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["messages"], &msgs))

	var tcs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msgs[0]["tool_calls"], &tcs))

	var tcType string
	require.NoError(t, json.Unmarshal(tcs[0]["type"], &tcType))
	assert.Equal(t, "function", tcType)
}

func TestNormalizeOpenAIRequest_MultipleToolCalls(t *testing.T) {
	input := `{
		"messages": [
			{
				"role": "assistant",
				"tool_calls": [
					{"id": "a", "function": {"name": "tool1", "arguments": "{}"}},
					{"id": "b", "type": "function", "function": {"name": "tool2", "arguments": "{}"}},
					{"id": "c", "function": {"name": "tool3", "arguments": "{}"}}
				]
			}
		]
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["messages"], &msgs))

	var tcs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(msgs[0]["tool_calls"], &tcs))
	require.Len(t, tcs, 3)

	for i, tc := range tcs {
		var tcType string
		require.NoError(t, json.Unmarshal(tc["type"], &tcType))
		assert.Equal(t, "function", tcType, "tool_call[%d] should have type=function", i)
	}
}

func TestNormalizeOpenAIRequest_MultipleMessagesWithToolCalls(t *testing.T) {
	input := `{
		"messages": [
			{"role": "user", "content": "step 1"},
			{
				"role": "assistant",
				"tool_calls": [{"id": "a", "function": {"name": "t1", "arguments": "{}"}}]
			},
			{"role": "tool", "tool_call_id": "a", "content": "r1"},
			{
				"role": "assistant",
				"tool_calls": [{"id": "b", "function": {"name": "t2", "arguments": "{}"}}]
			},
			{"role": "tool", "tool_call_id": "b", "content": "r2"}
		]
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	var msgs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["messages"], &msgs))

	// Check both assistant messages (index 1 and 3)
	for _, idx := range []int{1, 3} {
		var tcs []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(msgs[idx]["tool_calls"], &tcs))
		require.Len(t, tcs, 1)

		var tcType string
		require.NoError(t, json.Unmarshal(tcs[0]["type"], &tcType))
		assert.Equal(t, "function", tcType, "messages[%d].tool_calls[0].type should be function", idx)
	}
}

func TestNormalizeOpenAIRequest_PreservesOtherFields(t *testing.T) {
	input := `{
		"model": "gpt-4",
		"messages": [
			{
				"role": "assistant",
				"content": "I'll search for that.",
				"tool_calls": [
					{"id": "abc", "function": {"name": "search", "arguments": "{\"q\":\"test\"}"}}
				]
			}
		],
		"temperature": 0.7,
		"max_tokens": 100
	}`

	out := NormalizeOpenAIRequest([]byte(input))

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &result))

	// Top-level fields preserved
	assert.Equal(t, "gpt-4", result["model"])
	assert.Equal(t, 0.7, result["temperature"])
	assert.Equal(t, float64(100), result["max_tokens"])

	// Message content preserved
	msgs := result["messages"].([]interface{})
	msg := msgs[0].(map[string]interface{})
	assert.Equal(t, "assistant", msg["role"])
	assert.Equal(t, "I'll search for that.", msg["content"])

	// Tool call fields preserved
	tcs := msg["tool_calls"].([]interface{})
	tc := tcs[0].(map[string]interface{})
	assert.Equal(t, "abc", tc["id"])
	fn := tc["function"].(map[string]interface{})
	assert.Equal(t, "search", fn["name"])
}

// ---------------------------------------------------------------------------
// isEmptyOrNull
// ---------------------------------------------------------------------------

func TestIsEmptyOrNull(t *testing.T) {
	tests := []struct {
		name   string
		input  json.RawMessage
		expect bool
	}{
		{"nil", nil, true},
		{"empty", json.RawMessage{}, true},
		{"null literal", json.RawMessage(`null`), true},
		{"empty string", json.RawMessage(`""`), true},
		{"non-empty string", json.RawMessage(`"function"`), false},
		{"number", json.RawMessage(`42`), false},
		{"object", json.RawMessage(`{}`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, isEmptyOrNull(tt.input))
		})
	}
}
