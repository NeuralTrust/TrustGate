// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

func anthropicToConverse(t *testing.T, body string) ConverseRequest {
	t.Helper()
	out, err := NewRegistry().AdaptRequest([]byte(body), FormatAnthropic, FormatBedrock)
	require.NoError(t, err)
	return decodeConverse(t, out)
}

func TestAnthropicToConverse_StructuredOutputTopKAndStrictTools(t *testing.T) {
	req := anthropicToConverse(t, `{
		"model":"claude","max_tokens":64,"top_k":40,
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"name":"lookup","strict":true,"input_schema":{"type":"object","properties":{},"additionalProperties":false}}],
		"output_config":{"format":{"type":"json_schema","schema":{"type":"object", "properties":{"a":{"type":"string"}},"additionalProperties":false}}}
	}`)

	assert.JSONEq(t, `{"top_k":40}`, mustJSON(t, req.AdditionalModelRequestFields))
	require.NotNil(t, req.OutputConfig)
	require.NotNil(t, req.OutputConfig.TextFormat)
	assert.Equal(t, "json_schema", req.OutputConfig.TextFormat.Type)
	require.NotNil(t, req.OutputConfig.TextFormat.Structure.JSONSchema)
	assert.Equal(t, `{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false}`,
		req.OutputConfig.TextFormat.Structure.JSONSchema.Schema, "the schema travels as a compact string")
	require.Len(t, req.ToolConfig.Tools, 1)
	require.NotNil(t, req.ToolConfig.Tools[0].ToolSpec.Strict)
	assert.True(t, *req.ToolConfig.Tools[0].ToolSpec.Strict)
}

func TestAnthropicToConverse_WithoutOptionsAddsNothing(t *testing.T) {
	out, err := NewRegistry().AdaptRequest([]byte(`{"model":"claude","max_tokens":64,"messages":[{"role":"user","content":"hi"}],
		"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"output_config":{"format":{"type":"text"}}}`),
		FormatAnthropic, FormatBedrock)
	require.NoError(t, err)

	keys := topLevelKeys(t, out)
	assert.NotContains(t, keys, "additionalModelRequestFields")
	assert.NotContains(t, keys, "outputConfig", "a format with no Converse spelling is left out")
	assert.NotContains(t, string(keys["toolConfig"]), "strict")
}

func TestConverseEncoder_OtherSourcesKeepTodaysDrop(t *testing.T) {
	out, err := NewRegistry().AdaptRequest([]byte(`{"model":"gpt","top_k":40,"messages":[{"role":"user","content":"hi"}],
		"response_format":{"type":"json_schema","json_schema":{"name":"x","schema":{"type":"object"}}}}`),
		FormatOpenAI, FormatBedrock)
	require.NoError(t, err)

	keys := topLevelKeys(t, out)
	assert.NotContains(t, keys, "additionalModelRequestFields")
	assert.NotContains(t, keys, "outputConfig")
}

func TestBedrockModelVendor(t *testing.T) {
	for model, want := range map[string]string{
		"anthropic.claude-sonnet-4-5-20250929-v1:0":                                         "anthropic",
		"us.anthropic.claude-opus-4-6-v1":                                                   "anthropic",
		"EU.Anthropic.Claude-Haiku-4-5":                                                     "anthropic",
		"arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-sonnet-4-5":           "anthropic",
		"arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-x":    "anthropic",
		"arn:aws:bedrock:eu-west-1:123456789012:application-inference-profile/hfeskwe5y945": "",
		"amazon.nova-pro-v1:0":                                                              "amazon",
		"us.meta.llama4-maverick-17b-instruct-v1:0":                                         "meta",
		"": "",
	} {
		assert.Equal(t, want, BedrockModelVendor(model), model)
	}
}

func TestGateAnthropicConverseFields(t *testing.T) {
	body := []byte(`{"model":"m","messages":[],"additionalModelRequestFields":{"top_k":40},
		"outputConfig":{"textFormat":{"type":"json_schema","structure":{"jsonSchema":{"schema":"{}"}}}},
		"toolConfig":{"tools":[{"toolSpec":{"name":"a","inputSchema":{"json":{}},"strict":true}},{"cachePoint":{"type":"default"}}]}}`)

	for _, model := range []string{"us.anthropic.claude-opus-4-6-v1", "arn:aws:bedrock:eu-west-1:1:application-inference-profile/x"} {
		for _, drop := range []bool{false, true} {
			out, dropped, err := GateAnthropicConverseFields(body, model, drop)
			require.NoError(t, err, model)
			assert.Empty(t, dropped)
			assert.Equal(t, body, out, "Claude, or a model the ID hides, gets every field: %s", model)
		}
	}

	_, _, err := GateAnthropicConverseFields(body, "amazon.nova-pro-v1:0", false)
	var unsupported *AnthropicFieldsUnsupportedError
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, []string{"top_k"}, unsupported.Fields)
	assert.Contains(t, err.Error(), "amazon.nova-pro-v1:0")

	converseOnly := []byte(`{"messages":[],"outputConfig":{"textFormat":{}}}`)
	out, dropped, err := GateAnthropicConverseFields(converseOnly, "amazon.nova-pro-v1:0", false)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	assert.Equal(t, converseOnly, out, "Bedrock judges the Converse fields on the routed leg")

	out, dropped, err = GateAnthropicConverseFields(body, "us.meta.llama4-maverick-17b-instruct-v1:0", true)
	require.NoError(t, err)
	assert.Equal(t, []string{"top_k", "outputConfig", "toolSpec.strict"}, dropped)
	keys := topLevelKeys(t, out)
	assert.NotContains(t, keys, "additionalModelRequestFields")
	assert.NotContains(t, keys, "outputConfig")
	assert.JSONEq(t, `"m"`, string(keys["model"]), "the gateway's own keys stay")
	assert.JSONEq(t, `{"tools":[{"toolSpec":{"name":"a","inputSchema":{"json":{}}}},{"cachePoint":{"type":"default"}}]}`, string(keys["toolConfig"]))

	clean := []byte(`{"messages":[]}`)
	for _, drop := range []bool{false, true} {
		out, dropped, err = GateAnthropicConverseFields(clean, "amazon.nova-pro-v1:0", drop)
		require.NoError(t, err)
		assert.Empty(t, dropped)
		assert.Equal(t, clean, out)
	}
}

func TestAnthropicKeysUnmappedOnConverse(t *testing.T) {
	got := AnthropicKeysUnmappedOnConverse([]byte(`{"model":"m","messages":[],"max_tokens":1,"thinking":{"type":"adaptive"},
		"metadata":{"user_id":"u"},"context_management":{},"output_config":{"format":{},"effort":"high"}}`))
	assert.Equal(t, []string{"context_management", "metadata"}, got)
	assert.Nil(t, AnthropicKeysUnmappedOnConverse([]byte(`not json`)))
}

func TestHasAmbiguousKeys_OutputConfig(t *testing.T) {
	assert.True(t, HasAmbiguousKeys(FormatAnthropic, []byte(`{"messages":[],"output_config":{"format":{"type":"json_schema","Type":"text"}}}`)))
	assert.False(t, HasAmbiguousKeys(FormatAnthropic, []byte(`{"messages":[],"output_config":{"format":{"type":"json_schema","schema":{"Name":1,"name":2}}}}`)),
		"the schema belongs to the client")
	assert.True(t, HasAmbiguousKeys(FormatBedrock, []byte(`{"messages":[],"outputConfig":{},"OutputConfig":{}}`)))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

func TestAnthropicToConverse_ThinkingAndEffort(t *testing.T) {
	req := anthropicToConverse(t, `{"model":"claude","max_tokens":4096,"messages":[{"role":"user","content":"hi"}],
		"thinking":{"type":"adaptive","display":"summarized"},"output_config":{"effort":"high"}}`)

	assert.JSONEq(t, `{"thinking":{"type":"adaptive","display":"summarized"},"output_config":{"effort":"high"}}`,
		mustJSON(t, req.AdditionalModelRequestFields), "thinking travels verbatim")
	assert.Nil(t, req.OutputConfig, "effort is not a textFormat")
}

func TestAnthropicToConverse_HistoryKeepsSignedReasoning(t *testing.T) {
	req := anthropicToConverse(t, `{"model":"claude","max_tokens":4096,"messages":[
		{"role":"user","content":"weather?"},
		{"role":"assistant","content":[
			{"type":"thinking","thinking":"need the tool","signature":"sig-1"},
			{"type":"redacted_thinking","data":"AQID"},
			{"type":"text","text":"Checking."},
			{"type":"tool_use","id":"tu_1","name":"get_weather","input":{"city":"Madrid"}}]},
		{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":"sunny"}]}],
		"tools":[{"name":"get_weather","input_schema":{"type":"object"}}]}`)

	require.Len(t, req.Messages, 3)
	content := req.Messages[1].Content
	require.Len(t, content, 4)
	require.NotNil(t, content[0].ReasoningContent)
	assert.Equal(t, &ConverseReasoningText{Text: "need the tool", Signature: "sig-1"}, content[0].ReasoningContent.ReasoningText)
	require.NotNil(t, content[1].ReasoningContent)
	assert.Equal(t, []byte{1, 2, 3}, content[1].ReasoningContent.RedactedContent, "the payload goes back as the bytes it came as")
	assert.Equal(t, "Checking.", content[2].Text)
	require.NotNil(t, content[3].ToolUse)
}

func TestConverseToAnthropic_ResponseKeepsSignatures(t *testing.T) {
	out, err := NewRegistry().AdaptResponse([]byte(`{"output":{"message":{"role":"assistant","content":[
		{"reasoningContent":{"reasoningText":{"text":"17 has no divisors","signature":"sig-a"}}},
		{"reasoningContent":{"redactedContent":"AQID"}},
		{"reasoningContent":{"reasoningText":{"text":"","signature":"sig-b"}}},
		{"text":"Yes."}]}},"stopReason":"end_turn","usage":{"inputTokens":1,"outputTokens":2,"totalTokens":3}}`),
		FormatAnthropic, FormatBedrock)
	require.NoError(t, err)

	var resp struct {
		Content []map[string]any `json:"content"`
	}
	require.NoError(t, json.Unmarshal(out, &resp))
	require.Len(t, resp.Content, 4)
	assert.Equal(t, map[string]any{"type": "thinking", "thinking": "17 has no divisors", "signature": "sig-a"}, resp.Content[0])
	assert.Equal(t, map[string]any{"type": "redacted_thinking", "data": "AQID"}, resp.Content[1])
	assert.Equal(t, map[string]any{"type": "thinking", "thinking": "", "signature": "sig-b"}, resp.Content[2],
		"an omitted reasoning keeps its empty thinking field")
	assert.Equal(t, "Yes.", resp.Content[3]["text"])
}

func TestDropConverseAdditionalFields(t *testing.T) {
	out, dropped, err := DropConverseAdditionalFields([]byte(`{"messages":[],"additionalModelRequestFields":{"top_k":5,"thinking":{"type":"adaptive"}}}`),
		ConverseReasoningFields...)
	require.NoError(t, err)
	assert.Equal(t, []string{"thinking"}, dropped)
	assert.JSONEq(t, `{"top_k":5}`, string(topLevelKeys(t, out)["additionalModelRequestFields"]))

	body := []byte(`{"messages":[]}`)
	out, dropped, err = DropConverseAdditionalFields(body, ConverseReasoningFields...)
	require.NoError(t, err)
	assert.Empty(t, dropped)
	assert.Equal(t, body, out)
}

func TestAnthropicRedactedData_RoundTrip(t *testing.T) {
	for _, payload := range [][]byte{{0xff, 0x00, 0xfe}, []byte("plain text")} {
		assert.Equal(t, payload, anthropicRedactedBytes(anthropicRedactedData(payload)))
	}
	assert.Equal(t, []byte("not base64!"), anthropicRedactedBytes("not base64!"))
}

func TestStripConverseReasoningHistory(t *testing.T) {
	body := []byte(`{"model":"m","messages":[
		{"role":"user","content":[{"text":"q"}]},
		{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"t","signature":"s"}}},{"text":"a"}]},
		{"role":"user","content":[{"text":"q2"}]},
		{"role":"assistant","content":[{"reasoningContent":{"redactedContent":"AQID"}}]},
		{"role":"user","content":[{"text":"q3"}]}]}`)

	out, stripped, err := StripConverseReasoningHistory(body)
	require.NoError(t, err)
	assert.True(t, stripped)
	req := decodeConverse(t, out)
	require.Len(t, req.Messages, 3, "a turn left empty goes, and the user turns around it merge")
	assert.Equal(t, []ConverseContentBlock{{Text: "a"}}, req.Messages[1].Content)
	assert.Equal(t, []ConverseContentBlock{{Text: "q2"}, {Text: "q3"}}, req.Messages[2].Content)
	assert.JSONEq(t, `"m"`, string(topLevelKeys(t, out)["model"]))

	clean := []byte(`{"messages":[{"role":"user","content":[{"text":"q"}]}]}`)
	out, stripped, err = StripConverseReasoningHistory(clean)
	require.NoError(t, err)
	assert.False(t, stripped)
	assert.Equal(t, clean, out)
}
