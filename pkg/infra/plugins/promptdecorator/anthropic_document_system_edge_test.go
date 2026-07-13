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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnthropicDocumentTreatsBlankTextWithOpaqueBlockAsOpaque(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":" \n","cache_control":{"type":"ephemeral"}},{"type":"vendor","payload":{"x":1}}],"messages":[]}`)
	detected, err := hasAnthropicOriginalSystem(body)
	require.NoError(t, err)
	require.False(t, detected)

	document, err := decodeAnthropicDocument(body)
	require.NoError(t, err)
	require.False(t, document.system.loaded)
	require.Equal(t, anthropicSystemOpaque, document.loadSystemState())

	tests := []struct {
		name     string
		strategy systemStrategy
		expected string
	}{
		{
			name:     "merge",
			strategy: systemStrategyMerge,
			expected: `[{"type":"text","text":" \n","cache_control":{"type":"ephemeral"}},{"type":"vendor","payload":{"x":1}},{"type":"text","text":"new"}]`,
		},
		{
			name:     "append",
			strategy: systemStrategyAppend,
			expected: `[{"type":"text","text":" \n","cache_control":{"type":"ephemeral"}},{"type":"vendor","payload":{"x":1}},{"type":"text","text":"new"}]`,
		},
		{
			name:     "replace",
			strategy: systemStrategyReplace,
			expected: `[{"type":"text","text":"new"}]`,
		},
		{
			name:     "skip",
			strategy: systemStrategySkip,
			expected: `[{"type":"text","text":" \n","cache_control":{"type":"ephemeral"}},{"type":"vendor","payload":{"x":1}}]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := decorateAnthropicBody(
				body,
				[]decorator{anthropicTestSystemDecorator(test.strategy, "new")},
			)
			require.NoError(t, err)
			fields, _ := decodeAnthropicTestOutput(t, output)
			require.JSONEq(t, test.expected, string(fields["system"]))
		})
	}
}

func TestAnthropicDocumentAccumulatesManyStringMergesWithoutReencoding(t *testing.T) {
	const mergeCount = 2048
	decorators := make([]decorator, 0, mergeCount)
	expectedSegments := make([]string, 1, mergeCount+1)
	expectedSegments[0] = "base"
	for i := range mergeCount {
		content := fmt.Sprintf("m%d", i)
		decorators = append(decorators, anthropicTestSystemDecorator(systemStrategyMerge, content))
		expectedSegments = append(expectedSegments, content)
	}

	document, err := decodeAnthropicDocument([]byte(`{"system":"base","messages":[]}`))
	require.NoError(t, err)
	require.NoError(t, document.apply(decorators))
	require.Equal(t, expectedSegments, document.system.textSegments)
	require.Equal(t, json.RawMessage(`"base"`), document.system.raw)
	require.True(t, document.system.dirty)

	output, err := document.marshal()
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.Equal(t, strings.Join(expectedSegments, "\n\n"), anthropicTestSystemString(t, fields))
}

func TestAnthropicDocumentResetsStringSegmentsBeforeLaterMergesAndAppend(t *testing.T) {
	decorators := make([]decorator, 0, 1026)
	for i := range 512 {
		decorators = append(decorators, anthropicTestSystemDecorator(systemStrategyMerge, fmt.Sprintf("old%d", i)))
	}
	decorators = append(decorators, anthropicTestSystemDecorator(systemStrategyReplace, "replacement"))
	expectedSegments := []string{"replacement"}
	for i := range 512 {
		content := fmt.Sprintf("new%d", i)
		decorators = append(decorators, anthropicTestSystemDecorator(systemStrategyMerge, content))
		expectedSegments = append(expectedSegments, content)
	}
	decorators = append(decorators, anthropicTestSystemDecorator(systemStrategyAppend, "distinct"))

	document, err := decodeAnthropicDocument([]byte(`{"system":"base","messages":[]}`))
	require.NoError(t, err)
	require.NoError(t, document.apply(decorators))
	require.Equal(t, anthropicSystemKindBlocks, document.system.kind)
	require.Nil(t, document.system.textSegments)
	require.Len(t, document.system.blocks, 2)
	require.Equal(t, strings.Join(expectedSegments, "\n\n"), document.system.blocks[0].text)
	require.Equal(t, "distinct", document.system.blocks[1].text)

	output, err := document.marshal()
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.JSONEq(
		t,
		fmt.Sprintf(
			`[{"type":"text","text":%q},{"type":"text","text":"distinct"}]`,
			strings.Join(expectedSegments, "\n\n"),
		),
		string(fields["system"]),
	)
}

func TestAnthropicOriginalSystemDetection(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "nonblank string", body: `{"system":" rules "}`, expected: true},
		{name: "whitespace string", body: `{"system":" \t\n"}`},
		{name: "nonblank text block", body: `{"system":[{"type":"text","text":" rules "}]}`, expected: true},
		{name: "whitespace text blocks", body: `{"system":[{"type":"text","text":" "},{"type":"text","text":"\n"}]}`},
		{name: "mixed supported and unknown", body: `{"system":[{"type":"vendor","opaque":true},{"type":"text","text":"rules"}]}`, expected: true},
		{name: "unknown block only", body: `{"system":[{"type":"vendor","opaque":true}]}`},
		{name: "wrong text shape", body: `{"system":[{"type":"text","text":{"opaque":true}}]}`},
		{name: "opaque object", body: `{"system":{"text":"rules"}}`},
		{name: "opaque number", body: `{"system":7}`},
		{name: "null", body: `{"system":null}`},
		{name: "empty array", body: `{"system":[]}`},
		{name: "missing", body: `{"messages":[]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detected, err := hasAnthropicOriginalSystem([]byte(test.body))
			require.NoError(t, err)
			require.Equal(t, test.expected, detected)
		})
	}
}

func TestAnthropicOriginalSystemDetectionRejectsFieldAliases(t *testing.T) {
	tests := map[string]string{
		"uppercase system":  `{"SYSTEM":"rules"}`,
		"titlecase system":  `{"System":"rules"}`,
		"uppercase block":   `{"system":[{"TYPE":"text","TEXT":"rules"}]}`,
		"uppercase type":    `{"system":[{"TYPE":"text","text":"rules"}]}`,
		"uppercase text":    `{"system":[{"type":"text","TEXT":"rules"}]}`,
		"mixed exact/alias": `{"SYSTEM":"rules","system":" "}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := hasAnthropicOriginalSystem([]byte(body))
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
		})
	}
}

func TestAnthropicDocumentSystemStrategiesRejectFieldAliases(t *testing.T) {
	output, err := decorateAnthropicBody(
		[]byte(`{"system":[{"type":"text","text":"base"}],"messages":[]}`),
		[]decorator{anthropicTestSystemDecorator(systemStrategyMerge, "new")},
	)
	require.NoError(t, err)
	fields, _ := decodeAnthropicTestOutput(t, output)
	require.JSONEq(
		t,
		`[{"type":"text","text":"base"},{"type":"text","text":"\n\nnew"}]`,
		string(fields["system"]),
	)

	tests := map[string][]byte{
		"top-level system": []byte(`{"SYSTEM":"uppercase","messages":[]}`),
		"block fields":     []byte(`{"system":[{"TYPE":"text","TEXT":"base"}],"messages":[]}`),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := decorateAnthropicBody(
				body,
				[]decorator{anthropicTestSystemDecorator(systemStrategyMerge, "new")},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
		})
	}
}

func TestAnthropicOriginalSystemDetectionIgnoresUnrelatedFieldShapes(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":"rules"}],"messages":{"not":"an-array"},"metadata":{"large":[1,2,3,4,5],"number":1e10000},"unknown":[{"nested":true}]}`)
	detected, err := hasAnthropicOriginalSystem(body)
	require.NoError(t, err)
	require.True(t, detected)

	_, err = decorateAnthropicBody(body, []decorator{
		anthropicTestDecorator(positionEnd, roleUser, "new"),
	})
	require.EqualError(t, err, "prompt_decorator: Anthropic messages must be an array")
}
