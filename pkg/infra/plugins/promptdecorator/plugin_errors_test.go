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

func TestPluginExecuteEnforceReturnsStableBodyFreeRequestErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sourceFormat string
		body         []byte
		originalBody []byte
		settings     map[string]any
		errorType    string
	}{
		{
			name:         "malformed OpenAI folded body",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":["folded-secret"`),
			originalBody: []byte(`{"messages":[]}`),
			settings:     pluginDecoratorSettings("decorator-secret"),
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "malformed Anthropic folded body",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":["folded-secret"`),
			originalBody: []byte(`{"messages":[]}`),
			settings:     pluginDecoratorSettings("decorator-secret"),
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "malformed OpenAI original body",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"messages":["original-secret"`),
			settings:     map[string]any{"require_system_message": true},
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "malformed Anthropic original body",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"system":"original-secret"`),
			settings:     map[string]any{"require_system_message": true},
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "duplicate OpenAI folded protocol key",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[],"messages":[{"role":"user","content":"folded-secret"}]}`),
			originalBody: []byte(`{"messages":[]}`),
			settings:     pluginDecoratorSettings("decorator-secret"),
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "duplicate OpenAI original protocol key",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"messages":[{"role":"system","content":"original-secret","content":"other"}]}`),
			settings:     map[string]any{"require_system_message": true},
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "duplicate Anthropic original system",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"system":"original-secret","system":"other","messages":[]}`),
			settings:     map[string]any{"require_system_message": true},
			errorType:    typeInvalidRequestBody,
		},
		{
			name:         "required system on unsupported source",
			sourceFormat: "bedrock",
			body:         []byte(`folded-secret`),
			originalBody: []byte(`original-secret`),
			settings:     map[string]any{"require_system_message": true},
			errorType:    typeUnsupportedSource,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bodyBefore := append([]byte(nil), test.body...)
			originalBefore := append([]byte(nil), test.originalBody...)
			event, span := pluginEvent()
			input := pluginInput(
				policy.ModeEnforce,
				test.sourceFormat,
				test.body,
				test.originalBody,
				test.settings,
			)
			input.Event = event

			result, err := New().Execute(context.Background(), input)

			require.Nil(t, result)
			pluginError := requireBodyFreePluginError(t, err, test.errorType)
			require.NotContains(t, pluginError.Error(), "folded-secret")
			require.NotContains(t, pluginError.Error(), "original-secret")
			require.NotContains(t, pluginError.Error(), "decorator-secret")
			attributes, marshalErr := json.Marshal(span.PluginAttrsCopy())
			require.NoError(t, marshalErr)
			require.NotContains(t, string(attributes), "folded-secret")
			require.NotContains(t, string(attributes), "original-secret")
			require.NotContains(t, string(attributes), "decorator-secret")
			require.Equal(t, bodyBefore, test.body)
			require.Equal(t, originalBefore, test.originalBody)
		})
	}
}

func TestPluginExecuteObserveSuppressesMalformedRequestErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sourceFormat string
		body         []byte
		originalBody []byte
		settings     map[string]any
	}{
		{
			name:         "malformed OpenAI folded body",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":["folded-secret"`),
			originalBody: []byte(`{"messages":[]}`),
			settings:     pluginDecoratorSettings("decorator-secret"),
		},
		{
			name:         "malformed Anthropic folded body",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":["folded-secret"`),
			originalBody: []byte(`{"messages":[]}`),
			settings:     pluginDecoratorSettings("decorator-secret"),
		},
		{
			name:         "malformed OpenAI original body",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"messages":["original-secret"`),
			settings:     map[string]any{"require_system_message": true},
		},
		{
			name:         "malformed Anthropic original body",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"system":"original-secret"`),
			settings:     map[string]any{"require_system_message": true},
		},
		{
			name:         "duplicate OpenAI folded protocol key",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[],"messages":[{"role":"user","content":"folded-secret"}]}`),
			originalBody: []byte(`{"messages":[]}`),
			settings:     pluginDecoratorSettings("decorator-secret"),
		},
		{
			name:         "duplicate Anthropic original system",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":[]}`),
			originalBody: []byte(`{"system":"original-secret","system":"other"}`),
			settings:     map[string]any{"require_system_message": true},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bodyBefore := append([]byte(nil), test.body...)
			originalBefore := append([]byte(nil), test.originalBody...)
			event, span := pluginEvent()
			input := pluginInput(
				policy.ModeObserve,
				test.sourceFormat,
				test.body,
				test.originalBody,
				test.settings,
			)
			input.Event = event

			result, err := New().Execute(context.Background(), input)

			require.NoError(t, err)
			require.Equal(t, http.StatusOK, result.StatusCode)
			require.Nil(t, result.RequestBody)
			require.False(t, result.StopUpstream)
			attributes := span.PluginAttrsCopy()
			require.Equal(t, "observe", attributes.Decision)
			data, ok := attributes.Extras.(promptDecoratorData)
			require.True(t, ok)
			require.Equal(t, decisionParseError, data.Decision)
			require.True(t, data.ParseError)
			require.False(t, data.WouldDecorate)
			require.False(t, data.WouldReject)
			require.Empty(t, data.ErrorType)
			encoded, marshalErr := json.Marshal(attributes)
			require.NoError(t, marshalErr)
			require.NotContains(t, string(encoded), "folded-secret")
			require.NotContains(t, string(encoded), "original-secret")
			require.NotContains(t, string(encoded), "decorator-secret")
			require.NotContains(t, string(encoded), "unexpected")
			require.Equal(t, bodyBefore, test.body)
			require.Equal(t, originalBefore, test.originalBody)
		})
	}
}

func TestPluginExecuteUnsupportedSourceWithoutRequirementIsNoOp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sourceFormat string
		settings     map[string]any
	}{
		{name: "unsupported source", sourceFormat: "bedrock", settings: pluginDecoratorSettings("safe")},
		{name: "source format is not inferred", settings: pluginDecoratorSettings("safe")},
		{name: "observe requirement", sourceFormat: "bedrock", settings: map[string]any{"require_system_message": true}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mode := policy.ModeEnforce
			if test.name == "observe requirement" {
				mode = policy.ModeObserve
			}
			result, err := New().Execute(
				context.Background(),
				pluginInput(
					mode,
					test.sourceFormat,
					[]byte(`{"messages":[{"role":"system","content":"client"}]}`),
					[]byte(`not-json`),
					test.settings,
				),
			)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, result.StatusCode)
			require.Nil(t, result.RequestBody)
			require.False(t, result.StopUpstream)
		})
	}
}

func requireBodyFreePluginError(t *testing.T, err error, errorType string) *appplugins.PluginError {
	t.Helper()
	pluginError, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	require.Equal(t, http.StatusBadRequest, pluginError.StatusCode)
	require.Equal(t, errorType, pluginError.Type)
	require.Nil(t, pluginError.Body)
	require.Nil(t, pluginError.Headers)
	return pluginError
}
