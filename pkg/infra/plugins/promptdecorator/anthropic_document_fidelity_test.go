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

package promptdecorator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnthropicDocumentPreservesUnknownTopLevelSystemAndRichMessages(t *testing.T) {
	system := json.RawMessage(`[{"type": "text", "text": "rules", "cache_control":{"type":"ephemeral"}, "vendor":{"x":1}}, {"type":"vendor","payload":[1,true,null]}]`)
	first := json.RawMessage(`{"role": "user", "content": [{"type":"text","text":"hello","cache_control":{"type":"ephemeral"}}, {"type":"image","source":{"type":"base64","media_type":"image/png","data":"abc"}}], "custom": {"nested":[1,true,null]}}`)
	second := json.RawMessage(`{"role":"assistant","content":[{"type":"tool_use","id":"tool-1","name":"lookup","input":{"x":1}}],"stop_reason":"tool_use","vendor":7}`)
	body := []byte(`{"model":"claude-test","stream":true,"metadata":{"user_id":"u-1"},"vendor":{"flag":7},"system":` +
		string(system) + `,"messages":[` + string(first) + `,` + string(second) + `]}`)

	output, err := decorateAnthropicBody(body, []decorator{anthropicTestDecorator(positionEnd, roleUser, "new")})
	require.NoError(t, err)
	fields, messages := decodeAnthropicTestOutput(t, output)

	require.JSONEq(t, `"claude-test"`, string(fields["model"]))
	require.JSONEq(t, `true`, string(fields["stream"]))
	require.JSONEq(t, `{"user_id":"u-1"}`, string(fields["metadata"]))
	require.JSONEq(t, `{"flag":7}`, string(fields["vendor"]))
	require.Equal(t, system, fields["system"])
	require.Len(t, messages, 3)
	require.Equal(t, first, messages[0])
	require.Equal(t, second, messages[1])
	require.JSONEq(t, `{"role":"user","content":"new"}`, string(messages[2]))
}

func TestAnthropicDocumentPreservesOpaqueSystemOnNonSystemPlacement(t *testing.T) {
	system := json.RawMessage(`{"vendor": "opaque", "nested":[1,true,null]}`)
	output, err := decorateAnthropicBody(
		[]byte(`{"system":`+string(system)+`,"messages":[]}`),
		[]decorator{anthropicTestDecorator(positionAfterSystem, roleAssistant, "new")},
	)
	require.NoError(t, err)
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(t, system, fields["system"])
	require.Equal(t, []string{"assistant:new"}, anthropicTestMessageValues(t, messages))
}

func TestAnthropicDocumentHandlesMissingAndOpaqueMessageFields(t *testing.T) {
	output, err := decorateAnthropicBody(
		[]byte(`{"model":"claude-test","messages":[{"custom":true},{"role":7,"content":{"opaque":true}}]}`),
		[]decorator{
			anthropicTestDecorator(positionAfterSystem, roleUser, "first"),
			anthropicTestDecorator(positionBeforeLastUser, roleAssistant, "last"),
		},
	)
	require.NoError(t, err)
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.JSONEq(t, `"claude-test"`, string(fields["model"]))
	require.Len(t, messages, 4)
	require.JSONEq(t, `{"role":"assistant","content":"last"}`, string(messages[0]))
	require.JSONEq(t, `{"role":"user","content":"first"}`, string(messages[1]))
	require.JSONEq(t, `{"custom":true}`, string(messages[2]))
	require.JSONEq(t, `{"role":7,"content":{"opaque":true}}`, string(messages[3]))
}

func TestAnthropicDocumentExtractsRawFieldsAndClassifiesSystemLazily(t *testing.T) {
	system := json.RawMessage(`[{"type":"text","text":" "},{"type":"vendor","opaque":true}]`)
	document, err := decodeAnthropicDocument(
		[]byte(`{"model":"claude-test","system":` + string(system) + `,"messages":[{"role":"user","content":"u1"}]}`),
	)
	require.NoError(t, err)
	require.NotContains(t, document.fields, "messages")
	require.NotContains(t, document.fields, "system")
	require.False(t, document.system.loaded)
	require.False(t, document.messages.lastUserKnown)

	require.NoError(t, document.apply([]decorator{
		anthropicTestDecorator(positionEnd, roleAssistant, "new"),
	}))
	require.False(t, document.system.loaded)
	require.False(t, document.messages.lastUserKnown)

	output, err := document.marshal()
	require.NoError(t, err)
	require.NotContains(t, document.fields, "messages")
	require.NotContains(t, document.fields, "system")
	require.False(t, document.system.loaded)
	require.False(t, document.messages.lastUserKnown)
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(t, system, fields["system"])
	require.Equal(t, []string{"user:u1", "assistant:new"}, anthropicTestMessageValues(t, messages))
}

func TestAnthropicDocumentRejectsMalformedAndInvalidRequests(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "empty", wantErr: "prompt_decorator: decode Anthropic request: empty body"},
		{name: "malformed JSON", body: `{"messages":[}`, wantErr: "prompt_decorator: decode Anthropic request:"},
		{name: "array root", body: `[]`, wantErr: "prompt_decorator: Anthropic request must be a JSON object"},
		{name: "null root", body: `null`, wantErr: "prompt_decorator: Anthropic request must be a JSON object"},
		{name: "string messages", body: `{"messages":"opaque"}`, wantErr: "prompt_decorator: Anthropic messages must be an array"},
		{name: "object messages", body: `{"messages":{}}`, wantErr: "prompt_decorator: Anthropic messages must be an array"},
		{name: "null messages", body: `{"messages":null}`, wantErr: "prompt_decorator: Anthropic messages must be an array"},
		{name: "primitive message", body: `{"messages":[7]}`, wantErr: "prompt_decorator: Anthropic messages[0] must be an object"},
		{name: "null message", body: `{"messages":[null]}`, wantErr: "prompt_decorator: Anthropic messages[0] must be an object"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decorateAnthropicBody(
				[]byte(test.body),
				[]decorator{anthropicTestDecorator(positionEnd, roleUser, "new")},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.wantErr)
		})
	}
}

func TestAnthropicDocumentMarshalsDeterministicallyAndKeepsMetadataConsistent(t *testing.T) {
	document, err := decodeAnthropicDocument(
		[]byte(`{"z":1,"system":[{"z":true,"type":"text","text":"base","a":false}],"messages":[{"z":true,"role":"user","content":"u1","a":false}],"a":2}`),
	)
	require.NoError(t, err)
	require.NoError(t, document.apply([]decorator{
		anthropicTestSystemDecorator(systemStrategyMerge, "new"),
		anthropicTestDecorator(positionBeforeLastUser, roleAssistant, "before"),
		anthropicTestDecorator(positionBeforeLastUser, roleAssistant, "again"),
	}))

	expected := []byte(`{"a":2,"messages":[{"role":"assistant","content":"before"},{"role":"assistant","content":"again"},{"z":true,"role":"user","content":"u1","a":false}],"system":[{"z":true,"type":"text","text":"base","a":false},{"type":"text","text":"\n\nnew"}],"z":1}`)
	for range 100 {
		output, err := document.marshal()
		require.NoError(t, err)
		require.Equal(t, expected, output)
	}
}

func TestAnthropicDocumentHasBidirectionalAliasSafety(t *testing.T) {
	input := []byte(`{"model":"claude-test","system":[{"type":"text","text":"base"}],"messages":[{"role":"user","content":[{"type":"text","text":"original"}]}]}`)
	original := bytes.Clone(input)
	document, err := decodeAnthropicDocument(input)
	require.NoError(t, err)

	for i := range input {
		input[i] = 'x'
	}
	require.NoError(t, document.apply([]decorator{
		anthropicTestSystemDecorator(systemStrategyAppend, "rules"),
		anthropicTestDecorator(positionEnd, roleAssistant, "new"),
	}))
	output, err := document.marshal()
	require.NoError(t, err)
	require.JSONEq(
		t,
		`{"model":"claude-test","system":[{"type":"text","text":"base"},{"type":"text","text":"rules"}],"messages":[{"role":"user","content":[{"type":"text","text":"original"}]},{"role":"assistant","content":"new"}]}`,
		string(output),
	)

	outputSnapshot := bytes.Clone(output)
	output[0] = 'x'
	remarshaled, err := document.marshal()
	require.NoError(t, err)
	require.Equal(t, outputSnapshot, remarshaled)
	require.NotEqual(t, output, remarshaled)
	require.NotEqual(t, input, original)
}

func TestAnthropicDocumentAdditionLeavesOpenAIBehaviorUnchanged(t *testing.T) {
	output, err := decorateOpenAIBody(
		[]byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"base"},{"role":"user","content":"u1"}]}`),
		[]decorator{
			openAITestSystemDecorator(systemStrategyMerge, "rules"),
			openAITestDecorator(positionEnd, roleAssistant, "new"),
		},
	)
	require.NoError(t, err)
	require.JSONEq(
		t,
		`{"model":"gpt-4o","messages":[{"role":"system","content":"base\n\nrules"},{"role":"user","content":"u1"},{"role":"assistant","content":"new"}]}`,
		string(output),
	)
}

func FuzzDecorateAnthropicBodyNoPanicAndNoInputMutation(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"messages":[]}`),
		[]byte(`{"system":"base","messages":[{"role":"user","content":"u1"}]}`),
		[]byte(`{"system":[{"type":"text","text":"base","cache_control":{"type":"ephemeral"}},{"type":"vendor","x":1}],"messages":[],"unknown":true}`),
		[]byte(`{"system":{"opaque":true},"messages":[]}`),
		[]byte(`{"messages":"opaque"}`),
		[]byte(`{`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		snapshot := bytes.Clone(input)
		output, err := decorateAnthropicBody(
			input,
			[]decorator{anthropicTestSystemDecorator(systemStrategyMerge, "new")},
		)
		require.Equal(t, snapshot, input)
		if err != nil {
			return
		}
		require.True(t, json.Valid(output))
		if len(output) > 0 {
			output[0] ^= 0xff
			require.Equal(t, snapshot, input)
		}
	})
}

func FuzzAnthropicDocumentPreservesUntouchedMessage(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"role":"user","content":"hello"}`),
		[]byte(`{"role":"assistant","content":[{"type":"text","text":"hello"},{"type":"tool_use","id":"1"}]}`),
		[]byte(`{"custom":{"nested":[1,true,null]}}`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, message []byte) {
		if !json.Valid(message) || !isJSONObject(message) {
			return
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(message, &object); err != nil || object == nil {
			return
		}
		body := []byte(fmt.Sprintf(`{"messages":[%s]}`, message))
		output, err := decorateAnthropicBody(
			body,
			[]decorator{anthropicTestDecorator(positionEnd, roleUser, "new")},
		)
		require.NoError(t, err)
		_, messages := decodeAnthropicTestOutput(t, output)
		require.Len(t, messages, 2)
		require.Equal(t, bytes.TrimSpace(message), []byte(messages[0]))
	})
}
