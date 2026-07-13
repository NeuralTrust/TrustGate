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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnthropicDocumentPlacesMessagesAtAnchorsAndFallbacks(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		decorator decorator
		expected  []string
	}{
		{
			name:      "start",
			body:      `{"messages":[{"role":"user","content":"u1"},{"role":"assistant","content":"a1"}]}`,
			decorator: anthropicTestDecorator(positionStart, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1", "assistant:a1"},
		},
		{
			name:      "end",
			body:      `{"messages":[{"role":"user","content":"u1"}]}`,
			decorator: anthropicTestDecorator(positionEnd, roleAssistant, "new"),
			expected:  []string{"user:u1", "assistant:new"},
		},
		{
			name:      "after string system",
			body:      `{"system":"rules","messages":[{"role":"user","content":"u1"}]}`,
			decorator: anthropicTestDecorator(positionAfterSystem, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1"},
		},
		{
			name:      "after block system",
			body:      `{"system":[{"type":"text","text":"rules"}],"messages":[{"role":"user","content":"u1"}]}`,
			decorator: anthropicTestDecorator(positionAfterSystem, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1"},
		},
		{
			name:      "after opaque system",
			body:      `{"system":{"vendor":"opaque"},"messages":[{"role":"user","content":"u1"}]}`,
			decorator: anthropicTestDecorator(positionAfterSystem, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1"},
		},
		{
			name:      "after blank system falls back to start",
			body:      `{"system":" \n","messages":[{"role":"user","content":"u1"}]}`,
			decorator: anthropicTestDecorator(positionAfterSystem, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1"},
		},
		{
			name:      "after absent system falls back to start",
			body:      `{"messages":[{"role":"user","content":"u1"}]}`,
			decorator: anthropicTestDecorator(positionAfterSystem, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1"},
		},
		{
			name:      "before final user",
			body:      `{"messages":[{"role":"user","content":"u1"},{"role":"assistant","content":"a1"},{"role":"user","content":"u2"},{"role":"assistant","content":"a2"}]}`,
			decorator: anthropicTestDecorator(positionBeforeLastUser, roleAssistant, "new"),
			expected:  []string{"user:u1", "assistant:a1", "assistant:new", "user:u2", "assistant:a2"},
		},
		{
			name:      "before final user falls back to end",
			body:      `{"messages":[{"role":"assistant","content":"a1"}]}`,
			decorator: anthropicTestDecorator(positionBeforeLastUser, roleUser, "new"),
			expected:  []string{"assistant:a1", "user:new"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateAnthropicBody([]byte(test.body), []decorator{test.decorator})
			require.NoError(t, err)
			_, messages := decodeAnthropicTestOutput(t, output)
			require.Equal(t, test.expected, anthropicTestMessageValues(t, messages))
		})
	}
}

func TestAnthropicBeforeLastUserRejectsRoleAliases(t *testing.T) {
	tests := map[string]string{
		"uppercase role": `{"messages":[{"ROLE":"user","content":"upper"}]}`,
		"titlecase role": `{"messages":[{"Role":"user","content":"title"}]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := decorateAnthropicBody(
				[]byte(body),
				[]decorator{anthropicTestDecorator(positionBeforeLastUser, roleAssistant, "new")},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
		})
	}
}

func TestAnthropicDocumentAppliesDecoratorsSequentially(t *testing.T) {
	output, err := decorateAnthropicBody(
		[]byte(`{"system":"base","messages":[{"role":"user","content":"u1"},{"role":"assistant","content":"a1"}]}`),
		[]decorator{
			anthropicTestSystemDecorator(systemStrategyMerge, "first"),
			anthropicTestDecorator(positionAfterSystem, roleAssistant, "second"),
			anthropicTestDecorator(positionBeforeLastUser, roleAssistant, "third"),
			anthropicTestDecorator(positionEnd, roleUser, "fourth"),
			anthropicTestSystemDecorator(systemStrategyAppend, "fifth"),
		},
	)
	require.NoError(t, err)
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(
		t,
		[]string{"assistant:second", "assistant:third", "user:u1", "assistant:a1", "user:fourth"},
		anthropicTestMessageValues(t, messages),
	)

	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal(fields["system"], &blocks))
	require.Equal(t, []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{
		{Type: "text", Text: "base\n\nfirst"},
		{Type: "text", Text: "fifth"},
	}, blocks)
}

func TestAnthropicDocumentNeverAddsSystemRoleToMessages(t *testing.T) {
	output, err := decorateAnthropicBody(
		[]byte(`{"messages":[{"role":"user","content":"u1"}]}`),
		[]decorator{anthropicTestSystemDecorator(systemStrategySkip, "rules")},
	)
	require.NoError(t, err)
	fields, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(t, "rules", anthropicTestSystemString(t, fields))
	require.Equal(t, []string{"user:u1"}, anthropicTestMessageValues(t, messages))
}

func TestAnthropicDocumentHandlesManyAlternatingAnchorsInSequence(t *testing.T) {
	const decoratorCount = 512
	decorators := make([]decorator, 0, decoratorCount)
	expected := []string{"user:u0", "assistant:a0", "user:u1"}
	positions := []position{positionStart, positionEnd, positionBeforeLastUser, positionAfterSystem}

	for i := range decoratorCount {
		messageRole := roleAssistant
		if i%3 == 0 {
			messageRole = roleUser
		}
		content := fmt.Sprintf("d%d", i)
		messagePosition := positions[i%len(positions)]
		decorators = append(decorators, anthropicTestDecorator(messagePosition, messageRole, content))
		value := string(messageRole) + ":" + content

		switch messagePosition {
		case positionStart, positionAfterSystem:
			expected = append([]string{value}, expected...)
		case positionEnd:
			expected = append(expected, value)
		case positionBeforeLastUser:
			index := len(expected)
			for j := len(expected) - 1; j >= 0; j-- {
				if len(expected[j]) >= len("user:") && expected[j][:len("user:")] == "user:" {
					index = j
					break
				}
			}
			expected = append(expected, "")
			copy(expected[index+1:], expected[index:])
			expected[index] = value
		}
	}

	document, err := decodeAnthropicDocument(
		[]byte(`{"messages":[{"role":"user","content":"u0"},{"role":"assistant","content":"a0"},{"role":"user","content":"u1"}]}`),
	)
	require.NoError(t, err)
	require.NoError(t, document.apply(decorators))
	require.True(t, document.messages.lastUserKnown)
	require.Equal(t, decoratorCount+3, document.messages.length)

	output, err := document.marshal()
	require.NoError(t, err)
	_, messages := decodeAnthropicTestOutput(t, output)
	require.Equal(t, expected, anthropicTestMessageValues(t, messages))
}
