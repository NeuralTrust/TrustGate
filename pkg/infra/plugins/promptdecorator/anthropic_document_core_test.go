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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type anthropicTestMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func anthropicTestDecorator(messagePosition position, messageRole role, content string) decorator {
	return decorator{Position: messagePosition, Role: messageRole, Content: content}
}

func anthropicTestSystemDecorator(strategy systemStrategy, content string) decorator {
	return decorator{Position: positionSystem, Role: roleSystem, Content: content, OnExistingSystem: &strategy}
}

func decodeAnthropicTestOutput(t *testing.T, output []byte) (map[string]json.RawMessage, []json.RawMessage) {
	t.Helper()
	fields := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(output, &fields))
	var messages []json.RawMessage
	require.NoError(t, json.Unmarshal(fields["messages"], &messages))
	return fields, messages
}

func anthropicTestMessageValues(t *testing.T, rawMessages []json.RawMessage) []string {
	t.Helper()
	values := make([]string, len(rawMessages))
	for i := range rawMessages {
		var message anthropicTestMessage
		require.NoError(t, json.Unmarshal(rawMessages[i], &message))
		var content string
		require.NoError(t, json.Unmarshal(message.Content, &content))
		values[i] = message.Role + ":" + content
	}
	return values
}

func anthropicTestSystemString(t *testing.T, fields map[string]json.RawMessage) string {
	t.Helper()
	var system string
	require.NoError(t, json.Unmarshal(fields["system"], &system))
	return system
}

func TestDecorateAnthropicBodyCoreTransformation(t *testing.T) {
	input := []byte(`{"system":"base","messages":[{"role":"user","content":"original"}]}`)
	output, err := decorateAnthropicBody(input, []decorator{
		anthropicTestSystemDecorator(systemStrategyMerge, "rules"),
		anthropicTestDecorator(positionEnd, roleAssistant, "new"),
	})
	require.NoError(t, err)
	require.Equal(t, []byte(`{"system":"base","messages":[{"role":"user","content":"original"}]}`), input)

	input[0] = 'x'
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(t, "base\n\nrules", anthropicTestSystemString(t, fields))
	require.Equal(t, []string{"user:original", "assistant:new"}, anthropicTestMessageValues(t, messages))
	inputByte := input[1]
	output[1] ^= 0xff
	require.Equal(t, inputByte, input[1])
}

func TestHasAnthropicOriginalSystemCoreDetection(t *testing.T) {
	detected, err := hasAnthropicOriginalSystem(
		[]byte(`{"system":[{"type":"text","text":"rules","cache_control":{"type":"ephemeral"}}],"messages":[]}`),
	)
	require.NoError(t, err)
	require.True(t, detected)
}

func TestAnthropicDocumentLoadsSystemStateOnDemand(t *testing.T) {
	document, err := decodeAnthropicDocument(
		[]byte(`{"system":[{"type":"text","text":"rules"}],"messages":[]}`),
	)
	require.NoError(t, err)
	require.False(t, document.system.loaded)
	require.Equal(t, anthropicSystemNonblank, document.loadSystemState())
	require.True(t, document.system.loaded)
}

func TestAnthropicDocumentCreatesMessagesAndSystemWhenMissing(t *testing.T) {
	output, err := decorateAnthropicBody(
		[]byte(`{"model":"claude-test"}`),
		[]decorator{anthropicTestSystemDecorator(systemStrategySkip, "rules")},
	)
	require.NoError(t, err)
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(t, "rules", anthropicTestSystemString(t, fields))
	require.Empty(t, messages)
}

func TestAnthropicDocumentTracksSystemStateAcrossSequentialChanges(t *testing.T) {
	output, err := decorateAnthropicBody(
		[]byte(`{"system":[{"type":"text","text":" "}],"messages":[]}`),
		[]decorator{
			anthropicTestSystemDecorator(systemStrategySkip, "first"),
			anthropicTestSystemDecorator(systemStrategyMerge, "second"),
			anthropicTestSystemDecorator(systemStrategyAppend, "third"),
			anthropicTestSystemDecorator(systemStrategySkip, "ignored"),
		},
	)
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.JSONEq(
		t,
		`[{"type":"text","text":"first\n\nsecond"},{"type":"text","text":"third"}]`,
		string(fields["system"]),
	)
}
