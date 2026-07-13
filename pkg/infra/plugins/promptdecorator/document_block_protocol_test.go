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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemBlockExtractionRejectsFieldAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      []byte
		hasSystem func([]byte) (bool, error)
		transform func([]byte) ([]byte, error)
	}{
		{
			name:      "OpenAI wrong-case type",
			body:      []byte(`{"messages":[{"role":"system","content":[{"Type":"text","text":"prompt-secret"}]}]}`),
			hasSystem: hasOpenAIOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateOpenAIBody(
					body,
					[]decorator{openAITestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
		{
			name:      "OpenAI wrong-case text",
			body:      []byte(`{"messages":[{"role":"system","content":[{"type":"text","Text":"prompt-secret"}]}]}`),
			hasSystem: hasOpenAIOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateOpenAIBody(
					body,
					[]decorator{openAITestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
		{
			name:      "Anthropic wrong-case type",
			body:      []byte(`{"system":[{"Type":"text","text":"prompt-secret"}],"messages":[]}`),
			hasSystem: hasAnthropicOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateAnthropicBody(
					body,
					[]decorator{anthropicTestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
		{
			name:      "Anthropic wrong-case text",
			body:      []byte(`{"system":[{"type":"text","Text":"prompt-secret"}],"messages":[]}`),
			hasSystem: hasAnthropicOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateAnthropicBody(
					body,
					[]decorator{anthropicTestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := test.hasSystem(test.body)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")

			_, err = test.transform(test.body)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
		})
	}
}

func TestMessageContentBlocksRejectFieldAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      []byte
		transform func([]byte) ([]byte, error)
	}{
		{
			name: "OpenAI content block type",
			body: []byte(`{"messages":[{"role":"user","content":[{"Type":"text","text":"prompt-secret"}]}]}`),
			transform: func(body []byte) ([]byte, error) {
				return decorateOpenAIBody(
					body,
					[]decorator{openAITestDecorator(positionEnd, roleAssistant, "added")},
				)
			},
		},
		{
			name: "Anthropic content block text",
			body: []byte(`{"messages":[{"role":"user","content":[{"type":"text","Text":"prompt-secret"}]}]}`),
			transform: func(body []byte) ([]byte, error) {
				return decorateAnthropicBody(
					body,
					[]decorator{anthropicTestDecorator(positionEnd, roleAssistant, "added")},
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := test.transform(test.body)
			require.Nil(t, output)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
			require.NotContains(t, err.Error(), "prompt-secret")
		})
	}
}

func TestSystemBlockExtractionRejectsDuplicateExactFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      []byte
		hasSystem func([]byte) (bool, error)
		transform func([]byte) ([]byte, error)
	}{
		{
			name: "OpenAI duplicate type",
			body: []byte(
				`{"messages":[{"role":"system","content":[` +
					`{"type":"text","text":"valid"},` +
					`{"type":"text","type":"other","text":"prompt-secret"}` +
					`]}]}`,
			),
			hasSystem: hasOpenAIOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateOpenAIBody(
					body,
					[]decorator{openAITestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
		{
			name: "OpenAI duplicate text",
			body: []byte(
				`{"messages":[{"role":"system","content":[` +
					`{"type":"text","text":"valid"},` +
					`{"type":"text","text":"prompt-secret","text":"other"}` +
					`]}]}`,
			),
			hasSystem: hasOpenAIOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateOpenAIBody(
					body,
					[]decorator{openAITestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
		{
			name: "Anthropic duplicate type",
			body: []byte(
				`{"system":[` +
					`{"type":"text","text":"valid"},` +
					`{"type":"text","type":"other","text":"prompt-secret"}` +
					`],"messages":[]}`,
			),
			hasSystem: hasAnthropicOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateAnthropicBody(
					body,
					[]decorator{anthropicTestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
		{
			name: "Anthropic duplicate text",
			body: []byte(
				`{"system":[` +
					`{"type":"text","text":"valid"},` +
					`{"type":"text","text":"prompt-secret","text":"other"}` +
					`],"messages":[]}`,
			),
			hasSystem: hasAnthropicOriginalSystem,
			transform: func(body []byte) ([]byte, error) {
				return decorateAnthropicBody(
					body,
					[]decorator{anthropicTestDecorator(positionEnd, roleUser, "added")},
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := test.hasSystem(test.body)
			require.Error(t, err)
			require.Contains(t, err.Error(), "duplicate field")
			require.NotContains(t, err.Error(), "prompt-secret")

			output, err := test.transform(test.body)
			require.Nil(t, output)
			require.Error(t, err)
			require.Contains(t, err.Error(), "duplicate field")
			require.NotContains(t, err.Error(), "prompt-secret")
		})
	}
}
