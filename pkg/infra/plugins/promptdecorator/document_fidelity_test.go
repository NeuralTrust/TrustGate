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

func TestOpenAIDocumentTracksSystemMetadataAcrossSequentialChanges(t *testing.T) {
	output, err := decorateOpenAIBody(
		[]byte(`{"messages":[{"role":"system","content":" "},{"role":"user","content":"u1"}]}`),
		[]decorator{
			openAITestSystemDecorator(systemStrategySkip, "first"),
			openAITestSystemDecorator(systemStrategyMerge, "second"),
			openAITestSystemDecorator(systemStrategyAppend, "third"),
		},
	)
	require.NoError(t, err)
	_, messages := decodeOpenAITestOutput(t, output)
	require.Equal(
		t,
		[]string{"system: ", "system:first\n\nsecond", "system:third", "user:u1"},
		openAITestMessageValues(t, messages),
	)
}

func TestOpenAIDocumentPreservesUnknownTopLevelAndUntouchedMessages(t *testing.T) {
	untouched := json.RawMessage(`{"role": "user", "content": [{"type":"text","text":"hello"}, {"type":"image_url","image_url":{"url":"data:test"}}], "tool_calls": [{"id":"call-1","type":"function","function":{"name":"lookup","arguments":"{\"x\":1}"}}], "custom": {"nested":[1,true,null]}}`)
	body := []byte(`{"model":"gpt-4o","stream":true,"vendor":{"flag":7},"messages":[` + string(untouched) + `]}`)

	output, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleAssistant, "new")})
	require.NoError(t, err)
	fields, messages := decodeOpenAITestOutput(t, output)

	require.JSONEq(t, `"gpt-4o"`, string(fields["model"]))
	require.JSONEq(t, `true`, string(fields["stream"]))
	require.JSONEq(t, `{"flag":7}`, string(fields["vendor"]))
	require.Len(t, messages, 2)
	require.Equal(t, untouched, messages[0])
}

func TestOpenAIDocumentPreservesProtocolLikeKeysInsideUserObjects(t *testing.T) {
	metadata := json.RawMessage(`{"Role":"audit","Type":"trace","Content":{"Messages":[],"System":"nested"}}`)
	tools := json.RawMessage(`[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"Role":{"Type":"string"},"Content":{"Messages":[],"System":"schema"}}}}}]`)
	message := json.RawMessage(`{"role":"user","content":[{"type":"text","text":"hello","extension":{"Role":"viewer","Type":"custom","Content":{"Messages":[],"System":"block"}}}],"tool_calls":[{"type":"function","function":{"name":"lookup","arguments":{"Role":"operator","Type":"query","Content":{"Messages":[],"System":"argument"}}}}],"extension":{"Role":"user-data","Type":"message","Content":{"Messages":[],"System":"extension"}}}`)
	body := []byte(`{"metadata":` + string(metadata) + `,"tools":` + string(tools) + `,"messages":[` + string(message) + `]}`)

	output, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleAssistant, "new")})

	require.NoError(t, err)
	fields, messages := decodeOpenAITestOutput(t, output)
	require.Equal(t, metadata, fields["metadata"])
	require.Equal(t, tools, fields["tools"])
	require.Len(t, messages, 2)
	require.Equal(t, message, messages[0])
}

func TestOpenAIDocumentClearsDecodedRawMessagesUntilMarshal(t *testing.T) {
	document, err := decodeOpenAIDocument([]byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"u1"}]}`))
	require.NoError(t, err)
	require.NotContains(t, document.fields, "messages")

	output, err := document.marshal()
	require.NoError(t, err)
	fields, messages := decodeOpenAITestOutput(t, output)
	require.Contains(t, fields, "messages")
	require.Len(t, messages, 1)
}

func TestOpenAIDocumentMarshalsRawObjectsDeterministically(t *testing.T) {
	document, err := decodeOpenAIDocument(
		[]byte(`{"z":1,"messages":[{"z":true,"role":"system","content":"base","a":false}],"a":2}`),
	)
	require.NoError(t, err)
	require.NoError(t, document.apply([]decorator{openAITestSystemDecorator(systemStrategyMerge, "new")}))

	expected := []byte(`{"a":2,"messages":[{"a":false,"content":"base\n\nnew","role":"system","z":true}],"z":1}`)
	for range 100 {
		output, err := document.marshal()
		require.NoError(t, err)
		require.Equal(t, expected, output)
	}
}

func TestOpenAIOriginalSystemDetection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"whitespace string", `{"messages":[{"role":"system","content":" \t\n"}]}`, false},
		{"nonblank text block", `{"messages":[{"role":"system","content":[{"type":"text","text":" rules "}]}]}`, true},
		{"whitespace text block", `{"messages":[{"role":"system","content":[{"type":"text","text":" \n"}]}]}`, false},
		{"unsupported block", `{"messages":[{"role":"system","content":[{"type":"image_url","text":"rules"}]}]}`, false},
		{"any qualifying system", `{"messages":[{"role":"system","content":" "},{"role":"system","content":[{"type":"text","text":"rules"}]}]}`, true},
		{"developer does not count", `{"messages":[{"role":"developer","content":"rules"}]}`, false},
		{"non-text system content", `{"messages":[{"role":"system","content":{"text":"rules"}}]}`, false},
		{"missing messages", `{"model":"gpt-4o"}`, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detected, err := hasOpenAIOriginalSystem([]byte(test.body))
			require.NoError(t, err)
			require.Equal(t, test.expected, detected)
		})
	}
}

func TestOpenAIDocumentRejectsMalformedAndInvalidRequests(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"empty", "", "prompt_decorator: decode OpenAI request: empty body"},
		{"malformed JSON", `{"messages":[}`, "prompt_decorator: decode OpenAI request:"},
		{"array root", `[]`, "prompt_decorator: OpenAI request must be a JSON object"},
		{"null root", `null`, "prompt_decorator: OpenAI request must be a JSON object"},
		{"string messages", `{"messages":"opaque"}`, "prompt_decorator: OpenAI messages must be an array"},
		{"object messages", `{"messages":{}}`, "prompt_decorator: OpenAI messages must be an array"},
		{"null messages", `{"messages":null}`, "prompt_decorator: OpenAI messages must be an array"},
		{"primitive message", `{"messages":[7]}`, "prompt_decorator: OpenAI messages[0] must be an object"},
		{"null message", `{"messages":[null]}`, "prompt_decorator: OpenAI messages[0] must be an object"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decorateOpenAIBody(
				[]byte(test.body),
				[]decorator{openAITestDecorator(positionEnd, roleUser, "new")},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), test.wantErr)
		})
	}
}

func TestOpenAIDocumentHandlesMissingAndOpaqueMessageFields(t *testing.T) {
	output, err := decorateOpenAIBody(
		[]byte(`{"model":"gpt-4o","messages":[{"custom":true},{"role":7,"content":{"opaque":true}}]}`),
		[]decorator{
			openAITestDecorator(positionAfterSystem, roleUser, "first"),
			openAITestDecorator(positionBeforeLastUser, roleAssistant, "last"),
		},
	)
	require.NoError(t, err)
	fields, messages := decodeOpenAITestOutput(t, output)
	require.JSONEq(t, `"gpt-4o"`, string(fields["model"]))
	require.Len(t, messages, 4)
	require.JSONEq(t, `{"role":"assistant","content":"last"}`, string(messages[0]))
	require.JSONEq(t, `{"role":"user","content":"first"}`, string(messages[1]))
	require.JSONEq(t, `{"custom":true}`, string(messages[2]))
	require.JSONEq(t, `{"role":7,"content":{"opaque":true}}`, string(messages[3]))
}

func TestOpenAIDocumentRejectsOpaqueSystemContentOnlyWhenMergeRequiresIt(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":{"opaque":true},"custom":7}]}`)

	_, err := decorateOpenAIBody(body, []decorator{openAITestSystemDecorator(systemStrategyMerge, "new")})
	require.EqualError(t, err, "prompt_decorator: apply decorators[0]: OpenAI system content must be a string or array")

	output, err := decorateOpenAIBody(body, []decorator{openAITestSystemDecorator(systemStrategyAppend, "new")})
	require.NoError(t, err)
	_, messages := decodeOpenAITestOutput(t, output)
	require.Len(t, messages, 2)
	require.JSONEq(t, `{"role":"system","content":{"opaque":true},"custom":7}`, string(messages[0]))
	require.Equal(t, "new", openAITestStringContent(t, messages[1]))

	output, err = decorateOpenAIBody(body, []decorator{openAITestSystemDecorator(systemStrategySkip, "new")})
	require.NoError(t, err)
	_, messages = decodeOpenAITestOutput(t, output)
	require.Len(t, messages, 1)
	require.JSONEq(t, `{"role":"system","content":{"opaque":true},"custom":7}`, string(messages[0]))

	output, err = decorateOpenAIBody(body, []decorator{openAITestSystemDecorator(systemStrategyReplace, "new")})
	require.NoError(t, err)
	_, messages = decodeOpenAITestOutput(t, output)
	require.Len(t, messages, 1)
	require.JSONEq(t, `{"role":"system","content":"new","custom":7}`, string(messages[0]))
}

func TestOpenAIDocumentHasBidirectionalAliasSafety(t *testing.T) {
	input := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"original"}]}`)
	original := bytes.Clone(input)
	document, err := decodeOpenAIDocument(input)
	require.NoError(t, err)

	for i := range input {
		input[i] = 'x'
	}
	require.NoError(t, document.apply([]decorator{openAITestDecorator(positionEnd, roleAssistant, "new")}))
	output, err := document.marshal()
	require.NoError(t, err)
	require.JSONEq(
		t,
		`{"model":"gpt-4o","messages":[{"role":"user","content":"original"},{"role":"assistant","content":"new"}]}`,
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

func FuzzDecorateOpenAIBodyNoPanicAndNoInputMutation(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"messages":[]}`),
		[]byte(`{"messages":[{"role":"system","content":"base"}]}`),
		[]byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"base"}]}],"unknown":true}`),
		[]byte(`{"messages":"opaque"}`),
		[]byte(`{`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		snapshot := bytes.Clone(input)
		output, err := decorateOpenAIBody(
			input,
			[]decorator{openAITestSystemDecorator(systemStrategyMerge, "new")},
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

func FuzzOpenAIDocumentPreservesUntouchedMessage(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{"role":"user","content":"hello"}`),
		[]byte(`{"role":"assistant","content":[{"type":"text","text":"hello"}],"tool_calls":[{"id":"1"}]}`),
		[]byte(`{"custom":{"nested":[1,true,null]}}`),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, message []byte) {
		if !json.Valid(message) || !isJSONObject(message) {
			return
		}
		if _, err := decodeProtocolMessage(message, "fuzz OpenAI message"); err != nil {
			return
		}
		body := []byte(fmt.Sprintf(`{"messages":[%s]}`, message))
		output, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleUser, "new")})
		require.NoError(t, err)
		_, messages := decodeOpenAITestOutput(t, output)
		require.Len(t, messages, 2)

		require.Equal(t, bytes.TrimSpace(message), []byte(messages[0]))
	})
}
