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

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/require"
)

type pluginBlockProtocolFixture struct {
	name          string
	sourceFormat  string
	validBody     []byte
	wrongCaseType []byte
	wrongCaseText []byte
	duplicateType []byte
	duplicateText []byte
}

func pluginBlockProtocolFixtures() []pluginBlockProtocolFixture {
	return []pluginBlockProtocolFixture{
		{
			name:          "OpenAI",
			sourceFormat:  sourceFormatOpenAI,
			validBody:     []byte(`{"messages":[]}`),
			wrongCaseType: []byte(`{"messages":[{"role":"system","content":[{"Type":"text","text":"prompt-secret"}]}]}`),
			wrongCaseText: []byte(`{"messages":[{"role":"system","content":[{"type":"text","Text":"prompt-secret"}]}]}`),
			duplicateType: []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"valid"},{"type":"text","type":"other","text":"prompt-secret"}]}]}`),
			duplicateText: []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"valid"},{"type":"text","text":"prompt-secret","text":"other"}]}]}`),
		},
		{
			name:          "Anthropic",
			sourceFormat:  sourceFormatAnthropic,
			validBody:     []byte(`{"messages":[]}`),
			wrongCaseType: []byte(`{"system":[{"Type":"text","text":"prompt-secret"}],"messages":[]}`),
			wrongCaseText: []byte(`{"system":[{"type":"text","Text":"prompt-secret"}],"messages":[]}`),
			duplicateType: []byte(`{"system":[{"type":"text","text":"valid"},{"type":"text","type":"other","text":"prompt-secret"}],"messages":[]}`),
			duplicateText: []byte(`{"system":[{"type":"text","text":"valid"},{"type":"text","text":"prompt-secret","text":"other"}],"messages":[]}`),
		},
	}
}

func TestPluginSystemBlockFieldAliasesFollowModeContracts(t *testing.T) {
	t.Parallel()

	for _, fixture := range pluginBlockProtocolFixtures() {
		fixture := fixture
		tests := []struct {
			name string
			body []byte
		}{
			{name: "type", body: fixture.wrongCaseType},
			{name: "text", body: fixture.wrongCaseText},
		}
		for _, test := range tests {
			test := test
			t.Run(fixture.name+"/"+test.name+"/enforce", func(t *testing.T) {
				t.Parallel()
				input := pluginInput(
					policy.ModeEnforce,
					fixture.sourceFormat,
					fixture.validBody,
					test.body,
					map[string]any{"require_system_message": true},
				)
				result, err := New().Execute(context.Background(), input)
				require.Nil(t, result)
				pluginError := requireBodyFreePluginError(t, err, typeInvalidRequestBody)
				require.NotContains(t, pluginError.Error(), "prompt-secret")
			})
			t.Run(fixture.name+"/"+test.name+"/observe", func(t *testing.T) {
				t.Parallel()
				originalBefore := append([]byte(nil), test.body...)
				event, span := pluginEvent()
				input := pluginInput(
					policy.ModeObserve,
					fixture.sourceFormat,
					fixture.validBody,
					test.body,
					map[string]any{"require_system_message": true},
				)
				input.Event = event
				result, err := New().Execute(context.Background(), input)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, result.StatusCode)
				require.Nil(t, result.RequestBody)
				require.False(t, result.StopUpstream)
				data, ok := span.PluginAttrsCopy().Extras.(promptDecoratorData)
				require.True(t, ok)
				require.Equal(t, decisionParseError, data.Decision)
				require.False(t, data.WouldReject)
				require.True(t, data.ParseError)
				encoded, marshalErr := json.Marshal(span.PluginAttrsCopy())
				require.NoError(t, marshalErr)
				require.NotContains(t, string(encoded), "prompt-secret")
				require.Equal(t, originalBefore, test.body)
			})
		}
	}
}

func TestPluginSystemBlockDuplicateFieldsFollowModeContracts(t *testing.T) {
	t.Parallel()

	for _, fixture := range pluginBlockProtocolFixtures() {
		fixture := fixture
		tests := []struct {
			name string
			body []byte
		}{
			{name: "type", body: fixture.duplicateType},
			{name: "text", body: fixture.duplicateText},
		}
		for _, test := range tests {
			test := test
			for _, location := range []string{"original", "folded"} {
				location := location
				t.Run(fixture.name+"/"+test.name+"/"+location+"/enforce", func(t *testing.T) {
					t.Parallel()
					body, originalBody, settings := pluginBlockDuplicateInput(
						fixture,
						test.body,
						location,
					)
					bodyBefore := append([]byte(nil), body...)
					originalBefore := append([]byte(nil), originalBody...)
					event, span := pluginEvent()
					input := pluginInput(
						policy.ModeEnforce,
						fixture.sourceFormat,
						body,
						originalBody,
						settings,
					)
					input.Event = event
					result, err := New().Execute(context.Background(), input)
					require.Nil(t, result)
					pluginError := requireBodyFreePluginError(t, err, typeInvalidRequestBody)
					require.NotContains(t, pluginError.Error(), "prompt-secret")
					require.NotContains(t, pluginError.Error(), "decorator-secret")
					encoded, marshalErr := json.Marshal(span.PluginAttrsCopy())
					require.NoError(t, marshalErr)
					require.NotContains(t, string(encoded), "prompt-secret")
					require.NotContains(t, string(encoded), "decorator-secret")
					require.Equal(t, bodyBefore, body)
					require.Equal(t, originalBefore, originalBody)
				})
				t.Run(fixture.name+"/"+test.name+"/"+location+"/observe", func(t *testing.T) {
					t.Parallel()
					body, originalBody, settings := pluginBlockDuplicateInput(
						fixture,
						test.body,
						location,
					)
					bodyBefore := append([]byte(nil), body...)
					originalBefore := append([]byte(nil), originalBody...)
					event, span := pluginEvent()
					input := pluginInput(
						policy.ModeObserve,
						fixture.sourceFormat,
						body,
						originalBody,
						settings,
					)
					input.Event = event
					result, err := New().Execute(context.Background(), input)
					require.NoError(t, err)
					require.Equal(t, http.StatusOK, result.StatusCode)
					require.Nil(t, result.RequestBody)
					require.False(t, result.StopUpstream)
					data, ok := span.PluginAttrsCopy().Extras.(promptDecoratorData)
					require.True(t, ok)
					require.Equal(t, decisionParseError, data.Decision)
					require.True(t, data.ParseError)
					require.False(t, data.WouldDecorate)
					require.False(t, data.WouldReject)
					encoded, marshalErr := json.Marshal(span.PluginAttrsCopy())
					require.NoError(t, marshalErr)
					require.NotContains(t, string(encoded), "prompt-secret")
					require.NotContains(t, string(encoded), "decorator-secret")
					require.NotContains(t, string(encoded), "duplicate field")
					require.Equal(t, bodyBefore, body)
					require.Equal(t, originalBefore, originalBody)
				})
			}
		}
	}
}

func pluginBlockDuplicateInput(
	fixture pluginBlockProtocolFixture,
	invalidBody []byte,
	location string,
) ([]byte, []byte, map[string]any) {
	if location == "original" {
		return fixture.validBody, invalidBody, map[string]any{"require_system_message": true}
	}
	return invalidBody, fixture.validBody, pluginDecoratorSettings("decorator-secret")
}
