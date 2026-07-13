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

func TestOpenAIOriginalSystemExtractionIsExactCaseSensitive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{
			name: "exact protocol keys",
			body: []byte(`{"messages":[{"role":"system","content":"rules"}]}`),
			want: true,
		},
		{
			name: "wrong-case messages",
			body: []byte(`{"Messages":[{"role":"system","content":"rules"}]}`),
		},
		{
			name: "wrong-case role",
			body: []byte(`{"messages":[{"Role":"system","content":"rules"}]}`),
		},
		{
			name: "wrong-case content",
			body: []byte(`{"messages":[{"role":"system","Content":"rules"}]}`),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := hasOpenAIOriginalSystem(test.body)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestOpenAIPlacementIgnoresWrongCaseProtocolKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      []byte
		decorator decorator
		expected  string
	}{
		{
			name:      "wrong-case top-level messages remain opaque",
			body:      []byte(`{"Messages":[{"role":"system","content":"opaque"}]}`),
			decorator: openAITestDecorator(positionAfterSystem, roleAssistant, "added"),
			expected:  `{"Messages":[{"role":"system","content":"opaque"}],"messages":[{"role":"assistant","content":"added"}]}`,
		},
		{
			name:      "wrong-case role is not a system anchor",
			body:      []byte(`{"messages":[{"Role":"system","Content":"opaque"},{"role":"user","content":"exact"}]}`),
			decorator: openAITestDecorator(positionAfterSystem, roleAssistant, "added"),
			expected:  `{"messages":[{"role":"assistant","content":"added"},{"Role":"system","Content":"opaque"},{"role":"user","content":"exact"}]}`,
		},
		{
			name:      "wrong-case role is not a user anchor",
			body:      []byte(`{"messages":[{"role":"user","content":"exact"},{"Role":"user","Content":"opaque"}]}`),
			decorator: openAITestDecorator(positionBeforeLastUser, roleAssistant, "added"),
			expected:  `{"messages":[{"role":"assistant","content":"added"},{"role":"user","content":"exact"},{"Role":"user","Content":"opaque"}]}`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			output, err := decorateOpenAIBody(test.body, []decorator{test.decorator})
			require.NoError(t, err)
			require.JSONEq(t, test.expected, string(output))
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
