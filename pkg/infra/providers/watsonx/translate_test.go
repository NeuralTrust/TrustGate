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

package watsonx

import (
	"encoding/json"
	"errors"
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testProject = "0f8c3a52-7f4e-4d2b-9a61-2b7c0e5d9f13"

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out), "%s", raw)
	return out
}

func TestBuildChatRequest_MapsOpenAIFields(t *testing.T) {
	body := `{
		"model": "ibm/granite-4-h-small",
		"messages": [
			{"role": "developer", "content": [{"type": "text", "text": "Be brief."}, {"type": "text", "text": "Answer in German."}]},
			{"role": "user", "content": [{"type": "text", "text": "Weather?"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]},
			{"role": "assistant", "content": null, "refusal": null, "tool_calls": [
				{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Bonn\"}"}}
			]},
			{"role": "tool", "tool_call_id": "call_1", "content": [{"type": "text", "text": "12C"}]}
		],
		"tools": [
			{"type": "function", "function": {"name": "get_weather", "description": "Weather", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}, "strict": true}},
			{"type": "function", "function": {"name": "no_params"}},
			{"type": "web_search"}
		],
		"tool_choice": "required",
		"parallel_tool_calls": false,
		"max_completion_tokens": 256,
		"max_tokens": 64,
		"temperature": 0.2,
		"stop": "END",
		"stream": true,
		"stream_options": {"include_usage": true},
		"user": "u-1",
		"store": true,
		"project_id": "11111111-1111-1111-1111-111111111111",
		"space_id": "22222222-2222-2222-2222-222222222222",
		"guided_json": {"type": "object"}
	}`

	out, err := buildChatRequest([]byte(body), modelChoice{}, testProject)
	require.NoError(t, err)
	got := decode(t, out)

	assert.Equal(t, "ibm/granite-4-h-small", got["model_id"])
	assert.Equal(t, testProject, got["project_id"], "the registry's project always wins")
	assert.NotContains(t, got, "space_id")
	assert.NotContains(t, got, "model")
	for _, dropped := range []string{"stream", "stream_options", "user", "store", "parallel_tool_calls", "max_completion_tokens"} {
		assert.NotContains(t, got, dropped)
	}
	assert.EqualValues(t, 256, got["max_tokens"], "max_completion_tokens takes precedence")
	assert.EqualValues(t, 0.2, got["temperature"])
	assert.Equal(t, []any{"END"}, got["stop"])
	assert.Equal(t, "required", got["tool_choice_option"])
	assert.NotContains(t, got, "tool_choice")
	assert.Equal(t, map[string]any{"type": "object"}, got["guided_json"])

	msgs := got["messages"].([]any)
	require.Len(t, msgs, 4)
	assert.Equal(t, map[string]any{"role": "system", "content": "Be brief.\nAnswer in German."}, msgs[0])
	user := msgs[1].(map[string]any)
	assert.Equal(t, "user", user["role"])
	assert.Len(t, user["content"], 2, "user content parts, images included, pass through")
	assistant := msgs[2].(map[string]any)
	assert.NotContains(t, assistant, "content")
	assert.NotContains(t, assistant, "refusal")
	calls := assistant["tool_calls"].([]any)
	require.Len(t, calls, 1)
	assert.Equal(t, `{"city":"Bonn"}`, calls[0].(map[string]any)["function"].(map[string]any)["arguments"])
	assert.Equal(t, map[string]any{"role": "tool", "tool_call_id": "call_1", "content": "12C"}, msgs[3])

	tools := got["tools"].([]any)
	require.Len(t, tools, 2, "only function tools are sent")
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	assert.Equal(t, "get_weather", fn["name"])
	assert.NotContains(t, fn, "strict")
	noParams := tools[1].(map[string]any)["function"].(map[string]any)
	assert.Equal(t, map[string]any{"type": "object", "properties": map[string]any{}}, noParams["parameters"])
}

func TestBuildChatRequest_ModelPrecedence(t *testing.T) {
	body := []byte(`{"model":"from-body","messages":[{"role":"user","content":"hi"}]}`)

	out, err := buildChatRequest(body, modelChoice{configured: "configured", fallback: "fallback"}, testProject)
	require.NoError(t, err)
	assert.Equal(t, "configured", decode(t, out)["model_id"])

	out, err = buildChatRequest(body, modelChoice{fallback: "fallback"}, testProject)
	require.NoError(t, err)
	assert.Equal(t, "from-body", decode(t, out)["model_id"])

	out, err = buildChatRequest([]byte(`{"messages":[{"role":"user","content":"hi"}]}`), modelChoice{fallback: "fallback"}, testProject)
	require.NoError(t, err)
	assert.Equal(t, "fallback", decode(t, out)["model_id"])

	_, err = buildChatRequest([]byte(`{"messages":[{"role":"user","content":"hi"}]}`), modelChoice{}, testProject)
	assert.ErrorIs(t, err, errNoModel)
}

func TestBuildChatRequest_NamedToolChoice(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],
		"tool_choice":{"type":"function","function":{"name":"lookup"}}}`
	out, err := buildChatRequest([]byte(body), modelChoice{}, testProject)
	require.NoError(t, err)
	got := decode(t, out)
	assert.Equal(t, map[string]any{"type": "function", "function": map[string]any{"name": "lookup"}}, got["tool_choice"])
	assert.NotContains(t, got, "tool_choice_option")
}

func TestBuildChatRequest_ToolChoiceWithoutToolsIsDropped(t *testing.T) {
	out, err := buildChatRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"tool_choice":"auto"}`), modelChoice{}, testProject)
	require.NoError(t, err)
	got := decode(t, out)
	assert.NotContains(t, got, "tool_choice_option")
	assert.NotContains(t, got, "tools")
}

func TestBuildChatRequest_RejectsMalformedBodies(t *testing.T) {
	for name, body := range map[string]string{
		"not json":         `nope`,
		"array":            `[]`,
		"missing messages": `{"model":"m"}`,
		"messages object":  `{"model":"m","messages":{"role":"user"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildChatRequest([]byte(body), modelChoice{}, testProject)
			assert.Error(t, err)
		})
	}
}

func TestTranslateResponse_ToOpenAIChatCompletion(t *testing.T) {
	body := `{
		"id": "chatcmpl-abc",
		"model_id": "ibm/granite-4-h-small",
		"model_version": "4.0.0",
		"created": 1763040000,
		"created_at": "2026-11-13T12:00:00.000Z",
		"choices": [{
			"index": 0,
			"message": {"role": "assistant", "tool_calls": [
				{"id": "chatcmpl-tool-1", "type": "function", "function": {"name": "get_weather", "arguments": {"city": "Bonn"}}}
			]},
			"finish_reason": "tool_calls"
		}, {
			"index": 1,
			"message": {"role": "assistant", "content": "Hallo"},
			"finish_reason": "time_limit"
		}],
		"usage": {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19},
		"system": {"warnings": [{"message": "deprecated"}]}
	}`

	out, err := translateResponse([]byte(body))
	require.NoError(t, err)
	got := decode(t, out)

	assert.Equal(t, "chat.completion", got["object"])
	assert.Equal(t, "ibm/granite-4-h-small", got["model"])
	assert.EqualValues(t, 1763040000, got["created"])
	for _, dropped := range []string{"model_id", "model_version", "created_at", "system"} {
		assert.NotContains(t, got, dropped)
	}
	assert.Equal(t, map[string]any{"prompt_tokens": 12.0, "completion_tokens": 7.0, "total_tokens": 19.0}, got["usage"])

	choices := got["choices"].([]any)
	first := choices[0].(map[string]any)
	assert.Equal(t, "tool_calls", first["finish_reason"])
	call := first["message"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	assert.Equal(t, `{"city": "Bonn"}`, call["function"].(map[string]any)["arguments"], "object arguments become a JSON string")
	assert.Equal(t, "length", choices[1].(map[string]any)["finish_reason"])
}

func TestTranslateResponse_RejectsNonJSON(t *testing.T) {
	_, err := translateResponse([]byte("<html>"))
	assert.Error(t, err)
}

func lines(items ...string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, item := range items {
			if !yield([]byte(item), nil) {
				return
			}
		}
	}
}

func collect(t *testing.T, seq iter.Seq2[[]byte, error]) ([]string, error) {
	t.Helper()
	var out []string
	for line, err := range seq {
		if err != nil {
			return out, err
		}
		out = append(out, string(line))
	}
	return out, nil
}

func TestTranslateStream_ToOpenAIChunksAndDone(t *testing.T) {
	upstream := lines(
		"id: 1",
		"event: message",
		`data: {"id":"chatcmpl-1","model_id":"ibm/granite-4-h-small","created":1763040000,"created_at":"x","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`,
		"",
		"id: 2",
		"event: message",
		`data: {"id":"chatcmpl-1","model_id":"ibm/granite-4-h-small","created":1763040000,"choices":[{"index":0,"delta":{"tool_calls":[{"id":"call-1","function":{"name":"get_weather","arguments":""}}]}}]}`,
		"",
		"id: 3",
		"event: message",
		`data: {"id":"chatcmpl-1","model_id":"ibm/granite-4-h-small","created":1763040000,"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"Bonn\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`,
		"",
	)

	out, err := collect(t, translateStream(upstream))
	require.NoError(t, err)
	require.Equal(t, []string{"data: ", "", "data: ", "", "data: ", "", "data: [DONE]", ""}, prefixes(out))

	first := decode(t, []byte(out[0][len("data: "):]))
	assert.Equal(t, "chat.completion.chunk", first["object"])
	assert.Equal(t, "ibm/granite-4-h-small", first["model"])
	assert.NotContains(t, first, "model_id")
	assert.NotContains(t, first, "created_at")

	second := decode(t, []byte(out[2][len("data: "):]))
	call := second["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	assert.EqualValues(t, 0, call["index"], "a tool call delta without an index gets its position")
	assert.Equal(t, "function", call["type"])

	last := decode(t, []byte(out[4][len("data: "):]))
	assert.Equal(t, "tool_calls", last["choices"].([]any)[0].(map[string]any)["finish_reason"])
	assert.NotNil(t, last["usage"])
}

func prefixes(out []string) []string {
	res := make([]string, len(out))
	for i, line := range out {
		switch {
		case line == "data: [DONE]":
			res[i] = line
		case len(line) >= len("data: ") && line[:len("data: ")] == "data: ":
			res[i] = "data: "
		default:
			res[i] = line
		}
	}
	return res
}

func TestTranslateStream_ErrorEventBecomesOpenAIErrorChunk(t *testing.T) {
	upstream := lines(
		"id: 1",
		"event: message",
		`data: {"id":"c","model_id":"m","created":1,"choices":[{"index":0,"delta":{"content":"Hal"}}]}`,
		"",
		"id: 2",
		"event: error",
		`data: {"errors":[{"code":"model_overloaded","message":"Model is overloaded"}],"trace":"t-123","status_code":503}`,
		"",
		"id: 3",
		"event: message",
		`data: {"id":"c","model_id":"m","created":1,"choices":[{"index":0,"delta":{"content":"lo"}}]}`,
	)

	out, err := collect(t, translateStream(upstream))
	require.NoError(t, err)
	require.Len(t, out, 4)
	assert.NotContains(t, out, "data: [DONE]", "a failed stream does not claim to have finished")

	errChunk := decode(t, []byte(out[2][len("data: "):]))
	errObj := errChunk["error"].(map[string]any)
	assert.Equal(t, "model_overloaded", errObj["code"])
	assert.Equal(t, "api_error", errObj["type"])
	assert.Contains(t, errObj["message"], "Model is overloaded")
	assert.Contains(t, errObj["message"], "t-123")
}

func TestTranslateStream_PropagatesReadErrors(t *testing.T) {
	boom := errors.New("connection reset")
	upstream := func(yield func([]byte, error) bool) {
		if !yield([]byte(`data: {"id":"c","model_id":"m","created":1,"choices":[]}`), nil) {
			return
		}
		yield(nil, boom)
	}
	out, err := collect(t, translateStream(upstream))
	assert.ErrorIs(t, err, boom)
	assert.Len(t, out, 1)
}

func TestTranslateStream_StopsWhenConsumerStops(t *testing.T) {
	upstream := lines(
		`data: {"id":"c","model_id":"m","created":1,"choices":[]}`,
		`data: {"id":"c","model_id":"m","created":1,"choices":[]}`,
	)
	count := 0
	for range translateStream(upstream) {
		count++
		break
	}
	assert.Equal(t, 1, count)
}

func TestOpenAIErrorBody(t *testing.T) {
	t.Run("watsonx errors", func(t *testing.T) {
		got := decode(t, openAIErrorBody(404, []byte(`{"errors":[{"code":"model_not_supported","message":"Model 'x' is not supported"}],"trace":"abc","status_code":404}`)))
		errObj := got["error"].(map[string]any)
		assert.Equal(t, "model_not_supported", errObj["code"])
		assert.Equal(t, "not_found_error", errObj["type"])
		assert.Equal(t, "Model 'x' is not supported (watsonx trace abc)", errObj["message"])
	})
	t.Run("already openai shaped", func(t *testing.T) {
		body := []byte(`{"error":{"message":"m","type":"invalid_request_error"}}`)
		assert.Equal(t, body, openAIErrorBody(400, body))
	})
	t.Run("plain text", func(t *testing.T) {
		got := decode(t, openAIErrorBody(502, []byte("Bad Gateway")))
		assert.Equal(t, "Bad Gateway", got["error"].(map[string]any)["message"])
		assert.Equal(t, "api_error", got["error"].(map[string]any)["type"])
	})
	t.Run("empty body", func(t *testing.T) {
		got := decode(t, openAIErrorBody(429, nil))
		assert.Equal(t, "Too Many Requests", got["error"].(map[string]any)["message"])
		assert.Equal(t, "rate_limit_error", got["error"].(map[string]any)["type"])
	})
}
