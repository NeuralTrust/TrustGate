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

type openAITestMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func openAITestDecorator(messagePosition position, messageRole role, content string) decorator {
	return decorator{Position: messagePosition, Role: messageRole, Content: content}
}

func openAITestSystemDecorator(strategy systemStrategy, content string) decorator {
	return decorator{Position: positionSystem, Role: roleSystem, Content: content, OnExistingSystem: &strategy}
}

func decodeOpenAITestOutput(t *testing.T, output []byte) (map[string]json.RawMessage, []json.RawMessage) {
	t.Helper()
	fields := map[string]json.RawMessage{}
	require.NoError(t, json.Unmarshal(output, &fields))
	var messages []json.RawMessage
	require.NoError(t, json.Unmarshal(fields["messages"], &messages))
	return fields, messages
}

func openAITestMessageValues(t *testing.T, rawMessages []json.RawMessage) []string {
	t.Helper()
	values := make([]string, len(rawMessages))
	for i := range rawMessages {
		var message openAITestMessage
		require.NoError(t, json.Unmarshal(rawMessages[i], &message))
		values[i] = message.Role + ":" + openAITestStringContent(t, rawMessages[i])
	}
	return values
}

func openAITestStringContent(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var message openAITestMessage
	require.NoError(t, json.Unmarshal(raw, &message))
	var content string
	require.NoError(t, json.Unmarshal(message.Content, &content))
	return content
}

func TestDecorateOpenAIBodyCoreTransformation(t *testing.T) {
	input := []byte(`{"messages":[{"role":"user","content":"original"}]}`)
	decorators := []decorator{openAITestSystemDecorator(systemStrategySkip, "rules"), openAITestDecorator(positionEnd, roleAssistant, "new")}
	output, err := decorateOpenAIBody(input, decorators)
	require.NoError(t, err)
	require.Equal(t, []byte(`{"messages":[{"role":"user","content":"original"}]}`), input)

	input[0] = 'x'
	_, messages := decodeOpenAITestOutput(t, output)
	require.Equal(t, []string{"system:rules", "user:original", "assistant:new"}, openAITestMessageValues(t, messages))
	inputByte := input[1]
	output[1] ^= 0xff
	require.Equal(t, inputByte, input[1])
}

func TestHasOpenAIOriginalSystemCoreDetection(t *testing.T) {
	detected, err := hasOpenAIOriginalSystem([]byte(`{"messages":[{"role":"system","content":"rules"}]}`))
	require.NoError(t, err)
	require.True(t, detected)
}
