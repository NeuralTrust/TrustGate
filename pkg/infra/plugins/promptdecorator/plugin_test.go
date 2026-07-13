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
	"context"
	"encoding/json"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/require"
)

func TestPluginExecuteEnforceDecoratesSupportedFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sourceFormat string
		body         []byte
		expected     string
	}{
		{
			name:         "OpenAI",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"model":"gpt","messages":[{"role":"user","content":"hello"}]}`),
			expected:     `{"model":"gpt","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"safe"}]}`,
		},
		{
			name:         "Anthropic",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"model":"claude","messages":[{"role":"user","content":"hello"}]}`),
			expected:     `{"model":"claude","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"safe"}]}`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bodyBefore := append([]byte(nil), test.body...)
			result, err := New().Execute(
				context.Background(),
				pluginInput(policy.ModeEnforce, test.sourceFormat, test.body, test.body, pluginDecoratorSettings("safe")),
			)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, result.StatusCode)
			require.JSONEq(t, test.expected, string(result.RequestBody))
			require.Equal(t, bodyBefore, test.body)
		})
	}
}

func TestPluginExecuteRequiredSystemUsesOnlyOriginalBody(t *testing.T) {
	t.Parallel()

	settings := pluginDecoratorSettings("decorated")
	settings["require_system_message"] = true
	tests := []struct {
		name         string
		sourceFormat string
		body         []byte
		originalBody []byte
		wantReject   bool
	}{
		{
			name:         "folded OpenAI system cannot satisfy requirement",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[{"role":"system","content":"earlier plugin"},{"role":"user","content":"hello"}]}`),
			originalBody: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
			wantReject:   true,
		},
		{
			name:         "folded Anthropic system cannot satisfy requirement",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"system":"earlier plugin","messages":[{"role":"user","content":"hello"}]}`),
			originalBody: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
			wantReject:   true,
		},
		{
			name:         "original OpenAI system permits folded body decoration",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[{"role":"user","content":"folded"}]}`),
			originalBody: []byte(`{"messages":[{"role":"system","content":"client"},{"role":"user","content":"hello"}]}`),
		},
		{
			name:         "original Anthropic block system permits folded body decoration",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":[{"role":"user","content":"folded"}]}`),
			originalBody: []byte(`{"system":[{"type":"text","text":"client"}],"messages":[{"role":"user","content":"hello"}]}`),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := New().Execute(
				context.Background(),
				pluginInput(policy.ModeEnforce, test.sourceFormat, test.body, test.originalBody, settings),
			)
			if test.wantReject {
				require.Nil(t, result)
				requireRequiredSystemError(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, result.RequestBody)
			require.Contains(t, string(result.RequestBody), "folded")
			require.Contains(t, string(result.RequestBody), "decorated")
			require.NotContains(t, string(result.RequestBody), "client")
			require.NotContains(t, string(result.RequestBody), "hello")
		})
	}
}

func TestPluginExecuteRequiredSystemRejectsMissingOriginalForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sourceFormat string
		originalBody []byte
	}{
		{name: "nil OpenAI original", sourceFormat: sourceFormatOpenAI},
		{name: "empty OpenAI original", sourceFormat: sourceFormatOpenAI, originalBody: []byte{}},
		{name: "whitespace OpenAI original", sourceFormat: sourceFormatOpenAI, originalBody: []byte(" \n\t")},
		{name: "blank OpenAI system", sourceFormat: sourceFormatOpenAI, originalBody: []byte(`{"messages":[{"role":"system","content":"  "}]}`)},
		{name: "opaque OpenAI system", sourceFormat: sourceFormatOpenAI, originalBody: []byte(`{"messages":[{"role":"system","content":{"text":"rules"}}]}`)},
		{name: "wrong-case OpenAI role", sourceFormat: sourceFormatOpenAI, originalBody: []byte(`{"messages":[{"role":"System","content":"rules"}]}`)},
		{name: "wrong-case OpenAI messages key", sourceFormat: sourceFormatOpenAI, originalBody: []byte(`{"Messages":[{"role":"system","content":"rules"}]}`)},
		{name: "wrong-case OpenAI role key", sourceFormat: sourceFormatOpenAI, originalBody: []byte(`{"messages":[{"Role":"system","content":"rules"}]}`)},
		{name: "wrong-case OpenAI content key", sourceFormat: sourceFormatOpenAI, originalBody: []byte(`{"messages":[{"role":"system","Content":"rules"}]}`)},
		{name: "nil Anthropic original", sourceFormat: sourceFormatAnthropic},
		{name: "empty Anthropic original", sourceFormat: sourceFormatAnthropic, originalBody: []byte{}},
		{name: "blank Anthropic system", sourceFormat: sourceFormatAnthropic, originalBody: []byte(`{"system":"  ","messages":[]}`)},
		{name: "opaque Anthropic system", sourceFormat: sourceFormatAnthropic, originalBody: []byte(`{"system":{"text":"rules"},"messages":[]}`)},
		{name: "wrong-case Anthropic key", sourceFormat: sourceFormatAnthropic, originalBody: []byte(`{"System":"rules","messages":[]}`)},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := pluginInput(
				policy.ModeEnforce,
				test.sourceFormat,
				[]byte(`{"messages":[{"role":"user","content":"hello"}]}`),
				test.originalBody,
				map[string]any{"require_system_message": true},
			)
			result, err := New().Execute(context.Background(), input)
			require.Nil(t, result)
			requireRequiredSystemError(t, err)
		})
	}
}

func requireRequiredSystemError(t *testing.T, err error) {
	t.Helper()
	pluginError, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	require.Equal(t, http.StatusBadRequest, pluginError.StatusCode)
	require.Equal(t, typeSystemMessageRequired, pluginError.Type)
	require.Equal(t, []byte(`{"error":{"type":"system_message_required"}}`), pluginError.Body)
	require.Equal(t, map[string][]string{"Content-Type": {"application/json"}}, pluginError.Headers)
}

func TestPluginExecuteObserveNeverMutatesOrRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		settings     map[string]any
		wantDecorate bool
		wantReject   bool
	}{
		{
			name:         "would decorate",
			settings:     pluginDecoratorSettings("private prompt"),
			wantDecorate: true,
		},
		{
			name:       "would reject",
			settings:   map[string]any{"require_system_message": true},
			wantReject: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"messages":[{"role":"user","content":"private input"}]}`)
			original := append([]byte(nil), body...)
			event, span := pluginEvent()
			input := pluginInput(policy.ModeObserve, sourceFormatOpenAI, body, original, test.settings)
			input.Event = event

			result, err := New().Execute(context.Background(), input)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, result.StatusCode)
			require.Nil(t, result.RequestBody)
			require.False(t, result.StopUpstream)
			require.Equal(t, original, body)

			attributes := span.PluginAttrsCopy()
			require.Equal(t, "observe", attributes.Decision)
			data, ok := attributes.Extras.(promptDecoratorData)
			require.True(t, ok)
			require.Equal(t, decisionObserved, data.Decision)
			require.Equal(t, test.wantDecorate, data.WouldDecorate)
			require.Equal(t, test.wantReject, data.WouldReject)
			encoded, marshalErr := json.Marshal(data)
			require.NoError(t, marshalErr)
			require.NotContains(t, string(encoded), "private prompt")
			require.NotContains(t, string(encoded), "private input")
		})
	}
}

func TestPluginExecuteRequireOnlyAndNoOpTransforms(t *testing.T) {
	t.Parallel()

	t.Run("require only returns no request transform", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[{"role":"user","content":"folded"}]}`)
		original := []byte(`{"messages":[{"role":"system","content":"client"}]}`)
		result, err := New().Execute(
			context.Background(),
			pluginInput(
				policy.ModeEnforce,
				sourceFormatOpenAI,
				body,
				original,
				map[string]any{"require_system_message": true},
			),
		)
		require.NoError(t, err)
		require.Nil(t, result.RequestBody)
	})

	t.Run("skip existing system returns no request transform", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"system":"client","messages":[{"role":"user","content":"hello"}]}`)
		settings := map[string]any{
			"decorators": []any{
				map[string]any{
					"position":           "system",
					"role":               "system",
					"content":            "ignored",
					"on_existing_system": "skip",
				},
			},
		}
		result, err := New().Execute(
			context.Background(),
			pluginInput(policy.ModeEnforce, sourceFormatAnthropic, body, body, settings),
		)
		require.NoError(t, err)
		require.Nil(t, result.RequestBody)
	})
}
