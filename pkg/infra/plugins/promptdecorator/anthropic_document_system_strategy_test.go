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

func TestAnthropicDocumentAppliesStringSystemStrategies(t *testing.T) {
	tests := []struct {
		name     string
		strategy systemStrategy
		expected string
	}{
		{name: "merge", strategy: systemStrategyMerge, expected: `"base\n\nnew"`},
		{name: "replace", strategy: systemStrategyReplace, expected: `"new"`},
		{
			name:     "append",
			strategy: systemStrategyAppend,
			expected: `[{"type":"text","text":"base"},{"type":"text","text":"new"}]`,
		},
		{name: "skip", strategy: systemStrategySkip, expected: `"base"`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateAnthropicBody(
				[]byte(`{"system":"base","messages":[]}`),
				[]decorator{anthropicTestSystemDecorator(test.strategy, "new")},
			)
			require.NoError(t, err)
			fields, _ := decodeAnthropicTestOutput(t, output)
			require.JSONEq(t, test.expected, string(fields["system"]))
		})
	}
}

func TestAnthropicDocumentAppliesBlockSystemStrategies(t *testing.T) {
	originalFirst := json.RawMessage(`{"type":"text","text":"base","cache_control":{"type":"ephemeral"},"custom":7}`)
	originalSecond := json.RawMessage(`{"type":"vendor","payload":{"nested":[1,true,null]}}`)
	body := []byte(`{"system":[` + string(originalFirst) + `,` + string(originalSecond) + `],"messages":[]}`)

	tests := []struct {
		name          string
		strategy      systemStrategy
		expectedCount int
		expectedText  string
		preservesBase bool
	}{
		{name: "merge", strategy: systemStrategyMerge, expectedCount: 3, expectedText: "\n\nnew", preservesBase: true},
		{name: "replace", strategy: systemStrategyReplace, expectedCount: 1, expectedText: "new"},
		{name: "append", strategy: systemStrategyAppend, expectedCount: 3, expectedText: "new", preservesBase: true},
		{name: "skip", strategy: systemStrategySkip, expectedCount: 2, preservesBase: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateAnthropicBody(body, []decorator{anthropicTestSystemDecorator(test.strategy, "new")})
			require.NoError(t, err)
			fields, _ := decodeAnthropicTestOutput(t, output)

			var blocks []json.RawMessage
			require.NoError(t, json.Unmarshal(fields["system"], &blocks))
			require.Len(t, blocks, test.expectedCount)
			if test.preservesBase {
				require.Equal(t, originalFirst, blocks[0])
				require.Equal(t, originalSecond, blocks[1])
			}
			if test.expectedText != "" {
				var added struct {
					Type string `json:"type"`
					Text string `json:"text"`
				}
				require.NoError(t, json.Unmarshal(blocks[len(blocks)-1], &added))
				require.Equal(t, "text", added.Type)
				require.Equal(t, test.expectedText, added.Text)
			}
		})
	}
}

func TestAnthropicDocumentTreatsBlankSupportedSystemsAsAbsent(t *testing.T) {
	bodies := map[string]string{
		"string":       `{"system":" \t\n","messages":[]}`,
		"text block":   `{"system":[{"type":"text","text":" \n","cache_control":{"type":"ephemeral"}},{"type":"text","text":"\t"}],"messages":[]}`,
		"empty blocks": `{"system":[],"messages":[]}`,
		"null":         `{"system":null,"messages":[]}`,
	}
	strategies := []systemStrategy{
		systemStrategyMerge,
		systemStrategyReplace,
		systemStrategyAppend,
		systemStrategySkip,
	}

	for name, body := range bodies {
		for _, strategy := range strategies {
			t.Run(name+"/"+string(strategy), func(t *testing.T) {
				output, err := decorateAnthropicBody(
					[]byte(body),
					[]decorator{anthropicTestSystemDecorator(strategy, "new")},
				)
				require.NoError(t, err)
				fields, _ := decodeAnthropicTestOutput(t, output)
				require.JSONEq(t, `"new"`, string(fields["system"]))
			})
		}
	}
}

func TestAnthropicDocumentTreatsMixedBlocksAsMeaningful(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":" "},{"type":"vendor","opaque":true},{"type":"text","text":"base","cache_control":{"type":"ephemeral"}}],"messages":[]}`)
	output, err := decorateAnthropicBody(
		body,
		[]decorator{anthropicTestSystemDecorator(systemStrategyMerge, "new")},
	)
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)

	var blocks []json.RawMessage
	require.NoError(t, json.Unmarshal(fields["system"], &blocks))
	require.Len(t, blocks, 4)
	require.JSONEq(t, `{"type":"text","text":" "}`, string(blocks[0]))
	require.JSONEq(t, `{"type":"vendor","opaque":true}`, string(blocks[1]))
	require.JSONEq(
		t,
		`{"type":"text","text":"base","cache_control":{"type":"ephemeral"}}`,
		string(blocks[2]),
	)
	require.JSONEq(t, `{"type":"text","text":"\n\nnew"}`, string(blocks[3]))
}

func TestAnthropicDocumentHandlesOpaqueBlockSystems(t *testing.T) {
	body := []byte(`{"system":[{"type":"vendor","payload":{"x":1}}],"messages":[]}`)
	tests := []struct {
		name     string
		strategy systemStrategy
		expected string
	}{
		{
			name:     "merge",
			strategy: systemStrategyMerge,
			expected: `[{"type":"vendor","payload":{"x":1}},{"type":"text","text":"new"}]`,
		},
		{
			name:     "replace",
			strategy: systemStrategyReplace,
			expected: `[{"type":"text","text":"new"}]`,
		},
		{
			name:     "append",
			strategy: systemStrategyAppend,
			expected: `[{"type":"vendor","payload":{"x":1}},{"type":"text","text":"new"}]`,
		},
		{
			name:     "skip",
			strategy: systemStrategySkip,
			expected: `[{"type":"vendor","payload":{"x":1}}]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateAnthropicBody(body, []decorator{anthropicTestSystemDecorator(test.strategy, "new")})
			require.NoError(t, err)
			fields, _ := decodeAnthropicTestOutput(t, output)
			require.JSONEq(t, test.expected, string(fields["system"]))
		})
	}
}

func TestAnthropicDocumentHandlesOpaqueTopLevelSystem(t *testing.T) {
	body := []byte(`{"system":{"vendor":"opaque"},"messages":[]}`)

	output, err := decorateAnthropicBody(body, []decorator{anthropicTestSystemDecorator(systemStrategySkip, "new")})
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.JSONEq(t, `{"vendor":"opaque"}`, string(fields["system"]))

	output, err = decorateAnthropicBody(body, []decorator{anthropicTestSystemDecorator(systemStrategyReplace, "new")})
	require.NoError(t, err)
	fields, _ = decodeAnthropicTestOutput(t, output)
	require.JSONEq(t, `"new"`, string(fields["system"]))

	for _, strategy := range []systemStrategy{systemStrategyMerge, systemStrategyAppend} {
		t.Run(string(strategy), func(t *testing.T) {
			_, err := decorateAnthropicBody(body, []decorator{anthropicTestSystemDecorator(strategy, "new")})
			require.EqualError(
				t,
				err,
				"prompt_decorator: apply decorators[0]: anthropic system must be a string or array",
			)
		})
	}
}

func TestAnthropicDocumentDefersRepeatedStringSystemEncoding(t *testing.T) {
	document, err := decodeAnthropicDocument([]byte(`{"system":"base","messages":[]}`))
	require.NoError(t, err)
	require.NoError(t, document.apply([]decorator{
		anthropicTestSystemDecorator(systemStrategyMerge, "m1"),
		anthropicTestSystemDecorator(systemStrategySkip, "ignored"),
		anthropicTestSystemDecorator(systemStrategyAppend, "a1"),
		anthropicTestSystemDecorator(systemStrategyMerge, "m2"),
		anthropicTestSystemDecorator(systemStrategyReplace, "r1"),
		anthropicTestSystemDecorator(systemStrategySkip, "ignored"),
		anthropicTestSystemDecorator(systemStrategyAppend, "a2"),
		anthropicTestSystemDecorator(systemStrategyMerge, "m3"),
	}))

	require.True(t, document.system.dirty)
	require.Equal(t, json.RawMessage(`"base"`), document.system.raw)
	require.Equal(t, anthropicSystemKindBlocks, document.system.kind)
	require.Len(t, document.system.blocks, 3)
	for i := range document.system.blocks {
		require.True(t, document.system.blocks[i].generated)
		require.Nil(t, document.system.blocks[i].raw)
	}

	output, err := document.marshal()
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.JSONEq(
		t,
		`[{"type":"text","text":"r1"},{"type":"text","text":"a2"},{"type":"text","text":"\n\nm3"}]`,
		string(fields["system"]),
	)
}

func TestAnthropicDocumentDefersRepeatedBlockSystemEncoding(t *testing.T) {
	originalSystem := json.RawMessage(`[{"type":"text","text":"base","cache_control":{"type":"ephemeral"}},{"type":"vendor","payload":{"x":1}}]`)
	body := []byte(`{"system":` + string(originalSystem) + `,"messages":[]}`)
	snapshot := append([]byte(nil), body...)
	document, err := decodeAnthropicDocument(body)
	require.NoError(t, err)
	require.NoError(t, document.apply([]decorator{
		anthropicTestSystemDecorator(systemStrategyMerge, "m1"),
		anthropicTestSystemDecorator(systemStrategyAppend, "a1"),
		anthropicTestSystemDecorator(systemStrategySkip, "ignored"),
		anthropicTestSystemDecorator(systemStrategyMerge, "m2"),
	}))

	require.Equal(t, snapshot, body)
	require.Equal(t, originalSystem, document.system.raw)
	require.Len(t, document.system.blocks, 5)
	require.Equal(t, json.RawMessage(`{"type":"text","text":"base","cache_control":{"type":"ephemeral"}}`), document.system.blocks[0].raw)
	require.Equal(t, json.RawMessage(`{"type":"vendor","payload":{"x":1}}`), document.system.blocks[1].raw)
	for i := 2; i < len(document.system.blocks); i++ {
		require.True(t, document.system.blocks[i].generated)
		require.Nil(t, document.system.blocks[i].raw)
	}

	output, err := document.marshal()
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.JSONEq(
		t,
		`[{"type":"text","text":"base","cache_control":{"type":"ephemeral"}},{"type":"vendor","payload":{"x":1}},{"type":"text","text":"\n\nm1"},{"type":"text","text":"a1"},{"type":"text","text":"\n\nm2"}]`,
		string(fields["system"]),
	)

	require.NoError(t, document.apply([]decorator{
		anthropicTestSystemDecorator(systemStrategyReplace, "r1"),
		anthropicTestSystemDecorator(systemStrategySkip, "ignored"),
		anthropicTestSystemDecorator(systemStrategyAppend, "a2"),
		anthropicTestSystemDecorator(systemStrategyMerge, "m3"),
	}))
	output, err = document.marshal()
	require.NoError(t, err)
	fields, _ = decodeAnthropicTestOutput(t, output)
	require.JSONEq(
		t,
		`[{"type":"text","text":"r1"},{"type":"text","text":"a2"},{"type":"text","text":"\n\nm3"}]`,
		string(fields["system"]),
	)
}
