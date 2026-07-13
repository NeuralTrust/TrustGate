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

func TestOpenAIOriginalSystemExtractionRejectsProtocolAliases(t *testing.T) {
	t.Parallel()

	hasSystem, err := hasOpenAIOriginalSystem(
		[]byte(`{"messages":[{"role":"system","content":"rules"}]}`),
	)
	require.NoError(t, err)
	require.True(t, hasSystem)

	tests := map[string][]byte{
		"top-level messages": []byte(`{"Messages":[{"role":"system","content":"rules"}]}`),
		"message role":       []byte(`{"messages":[{"Role":"system","content":"rules"}]}`),
		"message content":    []byte(`{"messages":[{"role":"system","Content":"rules"}]}`),
	}

	for name, body := range tests {
		body := body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := hasOpenAIOriginalSystem(body)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
		})
	}
}

func TestOpenAIPlacementRejectsProtocolAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "top-level messages",
			body: []byte(`{"Messages":[{"role":"system","content":"opaque"}]}`),
		},
		{
			name: "message role",
			body: []byte(`{"messages":[{"Role":"system","content":"opaque"},{"role":"user","content":"exact"}]}`),
		},
		{
			name: "message content",
			body: []byte(`{"messages":[{"role":"user","Content":"opaque"}]}`),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := decorateOpenAIBody(
				test.body,
				[]decorator{openAITestDecorator(positionEnd, roleAssistant, "added")},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid field alias")
		})
	}
}

func TestProtocolDocumentsRejectDuplicateExactKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transform func([]byte) error
		body      []byte
	}{
		{
			name: "OpenAI duplicate messages",
			body: []byte(`{"messages":[],"messages":[]}`),
			transform: func(body []byte) error {
				_, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
		{
			name: "OpenAI duplicate role",
			body: []byte(`{"messages":[{"role":"user","role":"system","content":"rules"}]}`),
			transform: func(body []byte) error {
				_, err := hasOpenAIOriginalSystem(body)
				return err
			},
		},
		{
			name: "OpenAI duplicate content",
			body: []byte(`{"messages":[{"role":"system","content":"first","content":"second"}]}`),
			transform: func(body []byte) error {
				_, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
		{
			name: "Anthropic duplicate system extraction",
			body: []byte(`{"system":"first","system":"second","messages":[]}`),
			transform: func(body []byte) error {
				_, err := hasAnthropicOriginalSystem(body)
				return err
			},
		},
		{
			name: "Anthropic duplicate system transformation",
			body: []byte(`{"system":"first","system":"second","messages":[]}`),
			transform: func(body []byte) error {
				_, err := decorateAnthropicBody(body, []decorator{anthropicTestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
		{
			name: "OpenAI duplicate untouched top-level field",
			body: []byte(`{"future":{"enabled":true},"future":{"enabled":false},"messages":[]}`),
			transform: func(body []byte) error {
				_, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
		{
			name: "OpenAI duplicate untouched nested field",
			body: []byte(`{"extension":{"nested":{"secret":"first","secret":"second"}},"messages":[]}`),
			transform: func(body []byte) error {
				_, err := decorateOpenAIBody(body, []decorator{openAITestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
		{
			name: "Anthropic duplicate untouched message field",
			body: []byte(`{"messages":[{"role":"user","content":"hello","extension":1,"extension":2}]}`),
			transform: func(body []byte) error {
				_, err := decorateAnthropicBody(body, []decorator{anthropicTestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
		{
			name: "Anthropic duplicate untouched nested block field",
			body: []byte(`{"system":[{"type":"text","text":"rules","cache":{"ttl":1,"ttl":2}}],"messages":[]}`),
			transform: func(body []byte) error {
				_, err := decorateAnthropicBody(body, []decorator{anthropicTestDecorator(positionEnd, roleUser, "added")})
				return err
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.transform(test.body)
			require.Error(t, err)
			require.Contains(t, err.Error(), "duplicate field")
		})
	}
}

func TestDocumentTransformReportsChangesWithoutObserveMarshalling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		transform  func(bool) ([]byte, bool, error)
		wantChange bool
	}{
		{
			name: "OpenAI insertion",
			transform: func(marshalOutput bool) ([]byte, bool, error) {
				return transformOpenAIBody(
					[]byte(`{"messages":[{"role":"user","content":"client"}]}`),
					[]decorator{openAITestDecorator(positionEnd, roleAssistant, "added")},
					marshalOutput,
				)
			},
			wantChange: true,
		},
		{
			name: "OpenAI skip",
			transform: func(marshalOutput bool) ([]byte, bool, error) {
				return transformOpenAIBody(
					[]byte(`{"messages":[{"role":"system","content":"client"}]}`),
					[]decorator{openAITestSystemDecorator(systemStrategySkip, "ignored")},
					marshalOutput,
				)
			},
		},
		{
			name: "OpenAI identical replacement",
			transform: func(marshalOutput bool) ([]byte, bool, error) {
				return transformOpenAIBody(
					[]byte(`{"messages":[{"role":"system","content":"client"}]}`),
					[]decorator{openAITestSystemDecorator(systemStrategyReplace, "client")},
					marshalOutput,
				)
			},
		},
		{
			name: "Anthropic insertion",
			transform: func(marshalOutput bool) ([]byte, bool, error) {
				return transformAnthropicBody(
					[]byte(`{"messages":[{"role":"user","content":"client"}]}`),
					[]decorator{anthropicTestDecorator(positionEnd, roleAssistant, "added")},
					marshalOutput,
				)
			},
			wantChange: true,
		},
		{
			name: "Anthropic skip",
			transform: func(marshalOutput bool) ([]byte, bool, error) {
				return transformAnthropicBody(
					[]byte(`{"system":"client","messages":[]}`),
					[]decorator{anthropicTestSystemDecorator(systemStrategySkip, "ignored")},
					marshalOutput,
				)
			},
		},
		{
			name: "Anthropic identical replacement",
			transform: func(marshalOutput bool) ([]byte, bool, error) {
				return transformAnthropicBody(
					[]byte(`{"system":"client","messages":[]}`),
					[]decorator{anthropicTestSystemDecorator(systemStrategyReplace, "client")},
					marshalOutput,
				)
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observed, changed, err := test.transform(false)
			require.NoError(t, err)
			require.Nil(t, observed)
			require.Equal(t, test.wantChange, changed)

			enforced, changed, err := test.transform(true)
			require.NoError(t, err)
			require.Equal(t, test.wantChange, changed)
			if test.wantChange {
				require.NotEmpty(t, enforced)
			} else {
				require.Nil(t, enforced)
			}
		})
	}
}
