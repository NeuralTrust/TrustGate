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

func TestOpenAIDocumentPlacesMessagesAtAnchorsAndFallbacks(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		decorator decorator
		expected  []string
	}{
		{
			name:      "start",
			body:      `{"messages":[{"role":"user","content":"u1"},{"role":"assistant","content":"a1"}]}`,
			decorator: openAITestDecorator(positionStart, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1", "assistant:a1"},
		},
		{
			name:      "after full leading system prefix",
			body:      `{"messages":[{"role":"system","content":"s1"},{"role":"system","content":"s2"},{"role":"user","content":"u1"}]}`,
			decorator: openAITestDecorator(positionAfterSystem, roleUser, "new"),
			expected:  []string{"system:s1", "system:s2", "user:new", "user:u1"},
		},
		{
			name:      "after system falls back to start",
			body:      `{"messages":[{"role":"user","content":"u1"},{"role":"system","content":"late"}]}`,
			decorator: openAITestDecorator(positionAfterSystem, roleAssistant, "new"),
			expected:  []string{"assistant:new", "user:u1", "system:late"},
		},
		{
			name:      "before final user",
			body:      `{"messages":[{"role":"user","content":"u1"},{"role":"assistant","content":"a1"},{"role":"user","content":"u2"},{"role":"assistant","content":"a2"}]}`,
			decorator: openAITestDecorator(positionBeforeLastUser, roleAssistant, "new"),
			expected:  []string{"user:u1", "assistant:a1", "assistant:new", "user:u2", "assistant:a2"},
		},
		{
			name:      "before final user falls back to end",
			body:      `{"messages":[{"role":"assistant","content":"a1"}]}`,
			decorator: openAITestDecorator(positionBeforeLastUser, roleUser, "new"),
			expected:  []string{"assistant:a1", "user:new"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateOpenAIBody([]byte(test.body), []decorator{test.decorator})
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Equal(t, test.expected, openAITestMessageValues(t, messages))
		})
	}
}

func TestOpenAIDocumentAppliesExistingSystemStrategies(t *testing.T) {
	tests := []struct {
		name     string
		strategy systemStrategy
		expected []string
	}{
		{"merge", systemStrategyMerge, []string{"system:first\n\nnew", "system:second", "user:u1"}},
		{"replace", systemStrategyReplace, []string{"system:new", "system:second", "user:u1"}},
		{"append", systemStrategyAppend, []string{"system:first", "system:new", "system:second", "user:u1"}},
		{"skip", systemStrategySkip, []string{"system:first", "system:second", "user:u1"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"messages":[{"role":"system","content":"first"},{"role":"system","content":"second"},{"role":"user","content":"u1"}]}`)
			output, err := decorateOpenAIBody(body, []decorator{openAITestSystemDecorator(test.strategy, "new")})
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Equal(t, test.expected, openAITestMessageValues(t, messages))
		})
	}
}

func TestOpenAIDocumentTreatsBlankStringSystemsAsAbsent(t *testing.T) {
	strategies := []systemStrategy{
		systemStrategyMerge,
		systemStrategyReplace,
		systemStrategyAppend,
		systemStrategySkip,
	}
	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			output, err := decorateOpenAIBody(
				[]byte(`{"messages":[{"role":"system","content":" \t\n"},{"role":"user","content":"u1"}]}`),
				[]decorator{openAITestSystemDecorator(strategy, "new")},
			)
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Equal(
				t,
				[]string{"system: \t\n", "system:new", "user:u1"},
				openAITestMessageValues(t, messages),
			)
		})
	}
}

func TestOpenAIDocumentTreatsBlankBlockSystemsAsAbsent(t *testing.T) {
	for _, strategy := range []systemStrategy{systemStrategySkip, systemStrategyAppend} {
		t.Run(string(strategy), func(t *testing.T) {
			output, err := decorateOpenAIBody(
				[]byte(`{"messages":[{"role":"system","content":[{"type":"text","text":" \n"}],"custom":true},{"role":"user","content":"u1"}]}`),
				[]decorator{openAITestSystemDecorator(strategy, "new")},
			)
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Len(t, messages, 3)
			require.JSONEq(
				t,
				`{"role":"system","content":[{"type":"text","text":" \n"}],"custom":true}`,
				string(messages[0]),
			)
			require.Equal(t, "new", openAITestStringContent(t, messages[1]))
			require.Equal(t, "u1", openAITestStringContent(t, messages[2]))
		})
	}
}

func TestOpenAIDocumentTreatsSystemRoleWithoutContentAsAbsent(t *testing.T) {
	output, err := decorateOpenAIBody(
		[]byte(`{"messages":[{"role":"system","custom":true}]}`),
		[]decorator{openAITestSystemDecorator(systemStrategySkip, "new")},
	)
	require.NoError(t, err)
	_, messages := decodeOpenAITestOutput(t, output)
	require.Len(t, messages, 2)
	require.JSONEq(t, `{"role":"system","custom":true}`, string(messages[0]))
	require.Equal(t, "new", openAITestStringContent(t, messages[1]))
}

func TestOpenAIDocumentTreatsAllBlankSystemPrefixAsAbsent(t *testing.T) {
	strategies := []systemStrategy{
		systemStrategyMerge,
		systemStrategyReplace,
		systemStrategyAppend,
		systemStrategySkip,
	}
	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			output, err := decorateOpenAIBody(
				[]byte(`{"messages":[{"role":"system","content":" "},{"role":"system","content":[{"type":"text","text":" \n"},{"type":"text","text":"\t"}],"custom":true},{"role":"user","content":"u1"}]}`),
				[]decorator{openAITestSystemDecorator(strategy, "new")},
			)
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Len(t, messages, 4)
			require.JSONEq(t, `{"role":"system","content":" "}`, string(messages[0]))
			require.JSONEq(
				t,
				`{"role":"system","content":[{"type":"text","text":" \n"},{"type":"text","text":"\t"}],"custom":true}`,
				string(messages[1]),
			)
			require.Equal(t, "new", openAITestStringContent(t, messages[2]))
			require.Equal(t, "u1", openAITestStringContent(t, messages[3]))
		})
	}
}

func TestOpenAIDocumentTargetsFirstNonblankSystemAcrossMixedMessages(t *testing.T) {
	tests := []struct {
		name     string
		strategy systemStrategy
		expected []string
	}{
		{"merge", systemStrategyMerge, []string{"system: ", "system:target\n\nnew", "user:u1"}},
		{"replace", systemStrategyReplace, []string{"system: ", "system:new", "user:u1"}},
		{"append", systemStrategyAppend, []string{"system: ", "system:target", "system:new", "user:u1"}},
		{"skip", systemStrategySkip, []string{"system: ", "system:target", "user:u1"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateOpenAIBody(
				[]byte(`{"messages":[{"role":"system","content":" "},{"role":"system","content":"target"},{"role":"user","content":"u1"}]}`),
				[]decorator{openAITestSystemDecorator(test.strategy, "new")},
			)
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Equal(t, test.expected, openAITestMessageValues(t, messages))
		})
	}
}

func TestOpenAIDocumentTargetsFirstNonblankBlockSystem(t *testing.T) {
	for _, strategy := range []systemStrategy{systemStrategyMerge, systemStrategyReplace} {
		t.Run(string(strategy), func(t *testing.T) {
			output, err := decorateOpenAIBody(
				[]byte(`{"messages":[{"role":"system","content":[{"type":"text","text":" "}]},{"role":"system","content":[{"type":"text","text":"target"}],"custom":true}]}`),
				[]decorator{openAITestSystemDecorator(strategy, "new")},
			)
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.JSONEq(t, `{"role":"system","content":[{"type":"text","text":" "}]}`, string(messages[0]))

			var target struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
				Custom bool `json:"custom"`
			}
			require.NoError(t, json.Unmarshal(messages[1], &target))
			require.True(t, target.Custom)
			expected := []string{"new"}
			if strategy == systemStrategyMerge {
				expected = []string{"target", "\n\nnew"}
			}
			require.Len(t, target.Content, len(expected))
			for i := range expected {
				require.Equal(t, "text", target.Content[i].Type)
				require.Equal(t, expected[i], target.Content[i].Text)
			}
		})
	}
}

func TestOpenAIDocumentInsertsSystemWhenAbsentForRemainingStrategies(t *testing.T) {
	strategies := []systemStrategy{
		systemStrategyMerge,
		systemStrategyReplace,
		systemStrategyAppend,
	}
	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			output, err := decorateOpenAIBody(
				[]byte(`{"messages":[{"role":"user","content":"u1"}]}`),
				[]decorator{openAITestSystemDecorator(strategy, "new")},
			)
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)
			require.Equal(t, []string{"system:new", "user:u1"}, openAITestMessageValues(t, messages))
		})
	}
}

func TestOpenAIDocumentPreservesBlockRepresentationForMergeAndReplace(t *testing.T) {
	tests := []struct {
		name        string
		strategy    systemStrategy
		blockCount  int
		textByIndex map[int]string
	}{
		{"merge", systemStrategyMerge, 3, map[int]string{0: "base", 2: "\n\nnew"}},
		{"replace", systemStrategyReplace, 1, map[int]string{0: "new"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"base"},{"type":"image_url","image_url":{"url":"data:test"}}],"name":"guard"}]}`)
			output, err := decorateOpenAIBody(body, []decorator{openAITestSystemDecorator(test.strategy, "new")})
			require.NoError(t, err)
			_, messages := decodeOpenAITestOutput(t, output)

			var message struct {
				Content []json.RawMessage `json:"content"`
				Name    string            `json:"name"`
			}
			require.NoError(t, json.Unmarshal(messages[0], &message))
			require.Equal(t, "guard", message.Name)
			require.Len(t, message.Content, test.blockCount)
			for index, expectedText := range test.textByIndex {
				var block struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}
				require.NoError(t, json.Unmarshal(message.Content[index], &block))
				require.Equal(t, "text", block.Type)
				require.Equal(t, expectedText, block.Text)
			}
			if test.strategy == systemStrategyMerge {
				require.JSONEq(
					t,
					`{"type":"image_url","image_url":{"url":"data:test"}}`,
					string(message.Content[1]),
				)
			}
		})
	}
}

func TestOpenAIDocumentAppliesDecoratorsSequentially(t *testing.T) {
	output, err := decorateOpenAIBody(
		[]byte(`{"messages":[{"role":"system","content":"base"},{"role":"user","content":"u1"}]}`),
		[]decorator{
			openAITestSystemDecorator(systemStrategyMerge, "first"),
			openAITestSystemDecorator(systemStrategyMerge, "second"),
			openAITestDecorator(positionAfterSystem, roleAssistant, "third"),
		},
	)
	require.NoError(t, err)
	_, messages := decodeOpenAITestOutput(t, output)
	require.Equal(
		t,
		[]string{"system:base\n\nfirst\n\nsecond", "assistant:third", "user:u1"},
		openAITestMessageValues(t, messages),
	)
}
