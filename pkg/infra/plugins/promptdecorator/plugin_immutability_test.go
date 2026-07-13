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
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/require"
)

func TestPluginExecuteLeavesAllInputStorageUnchanged(t *testing.T) {
	t.Parallel()

	backing := make([]byte, 0, 256)
	backing = append(backing, []byte(`{"messages":[{"role":"system","content":"client"},{"role":"user","content":"hello"}]}`)...)
	body := backing[:len(backing):cap(backing)]
	originalBody := body
	settings := pluginDecoratorSettings("private decoration")
	headers := map[string][]string{"X-Test": {"one", "two"}}
	metadata := map[string]interface{}{"nested": map[string]interface{}{"value": "unchanged"}}
	request := &infracontext.RequestContext{
		SourceFormat: sourceFormatOpenAI,
		Body:         body,
		OriginalBody: originalBody,
		Headers:      headers,
		Metadata:     metadata,
	}
	input := appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: settings},
		Request: request,
	}

	bodyBefore := append([]byte(nil), body...)
	originalBefore := append([]byte(nil), originalBody...)
	settingsBefore, err := json.Marshal(settings)
	require.NoError(t, err)
	headersBefore, err := json.Marshal(headers)
	require.NoError(t, err)
	metadataBefore, err := json.Marshal(metadata)
	require.NoError(t, err)
	bodyAddress := &request.Body[0]
	originalAddress := &request.OriginalBody[0]

	result, err := New().Execute(context.Background(), input)
	require.NoError(t, err)
	require.NotEmpty(t, result.RequestBody)
	require.Equal(t, bodyBefore, request.Body)
	require.Equal(t, originalBefore, request.OriginalBody)
	require.Same(t, bodyAddress, &request.Body[0])
	require.Same(t, originalAddress, &request.OriginalBody[0])

	settingsAfter, err := json.Marshal(settings)
	require.NoError(t, err)
	headersAfter, err := json.Marshal(headers)
	require.NoError(t, err)
	metadataAfter, err := json.Marshal(metadata)
	require.NoError(t, err)
	require.Equal(t, settingsBefore, settingsAfter)
	require.Equal(t, headersBefore, headersAfter)
	require.Equal(t, metadataBefore, metadataAfter)
}

func TestPluginExecuteResultStorageIsIndependentInBothDirections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sourceFormat string
		body         []byte
	}{
		{
			name:         "OpenAI",
			sourceFormat: sourceFormatOpenAI,
			body:         []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
		},
		{
			name:         "Anthropic",
			sourceFormat: sourceFormatAnthropic,
			body:         []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			t.Run("input mutation cannot change result", func(t *testing.T) {
				body := append([]byte(nil), test.body...)
				result, err := New().Execute(
					context.Background(),
					pluginInput(policy.ModeEnforce, test.sourceFormat, body, body, pluginDecoratorSettings("safe")),
				)
				require.NoError(t, err)
				resultBefore := append([]byte(nil), result.RequestBody...)
				for i := range body {
					body[i] ^= 0xff
				}
				require.Equal(t, resultBefore, result.RequestBody)
			})

			t.Run("result mutation cannot change input", func(t *testing.T) {
				body := append([]byte(nil), test.body...)
				bodyBefore := append([]byte(nil), body...)
				result, err := New().Execute(
					context.Background(),
					pluginInput(policy.ModeEnforce, test.sourceFormat, body, body, pluginDecoratorSettings("safe")),
				)
				require.NoError(t, err)
				for i := range result.RequestBody {
					result.RequestBody[i] ^= 0xff
				}
				require.Equal(t, bodyBefore, body)
			})
		})
	}
}

func TestPluginExecutePreservesOpaqueFoldedMessages(t *testing.T) {
	t.Parallel()

	body := []byte(`{"messages":[{"role":17,"content":{"private":"value"},"unknown":[1,2,3]}]}`)
	result, err := New().Execute(
		context.Background(),
		pluginInput(policy.ModeEnforce, sourceFormatOpenAI, body, body, pluginDecoratorSettings("safe")),
	)
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result.RequestBody, &fields))
	var messages []json.RawMessage
	require.NoError(t, json.Unmarshal(fields["messages"], &messages))
	require.Len(t, messages, 2)
	require.JSONEq(t, `{"role":17,"content":{"private":"value"},"unknown":[1,2,3]}`, string(messages[0]))
	require.JSONEq(t, `{"role":"assistant","content":"safe"}`, string(messages[1]))
}

func TestPluginExecuteHasNoSharedStateAcrossConcurrentCalls(t *testing.T) {
	t.Parallel()

	const callCount = 32
	plugin := New()
	body := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	input := pluginInput(
		policy.ModeEnforce,
		sourceFormatOpenAI,
		body,
		body,
		pluginDecoratorSettings("safe"),
	)
	results := make([][]byte, callCount)
	errors := make([]error, callCount)

	var waitGroup sync.WaitGroup
	waitGroup.Add(callCount)
	for i := 0; i < callCount; i++ {
		i := i
		go func() {
			defer waitGroup.Done()
			result, err := plugin.Execute(context.Background(), input)
			errors[i] = err
			if result != nil {
				results[i] = result.RequestBody
			}
		}()
	}
	waitGroup.Wait()

	for i := 0; i < callCount; i++ {
		require.NoError(t, errors[i])
		require.NotEmpty(t, results[i])
		require.True(t, bytes.Equal(results[0], results[i]))
	}
	results[0][0] ^= 0xff
	for i := 1; i < callCount; i++ {
		require.NotEqual(t, results[0], results[i])
	}
	require.Equal(t, []byte(`{"messages":[{"role":"user","content":"hello"}]}`), body)
}

func TestPluginTelemetryContainsNoPromptContent(t *testing.T) {
	t.Parallel()

	event, span := pluginEvent()
	input := pluginInput(
		policy.ModeEnforce,
		sourceFormatAnthropic,
		[]byte(`{"system":"private original","messages":[{"role":"user","content":"private input"}]}`),
		[]byte(`{"system":"private original","messages":[{"role":"user","content":"private input"}]}`),
		pluginDecoratorSettings("private decoration"),
	)
	input.Event = event
	result, err := New().Execute(context.Background(), input)
	require.NoError(t, err)
	require.NotEmpty(t, result.RequestBody)

	attributes := span.PluginAttrsCopy()
	data, ok := attributes.Extras.(promptDecoratorData)
	require.True(t, ok)
	require.Equal(t, decisionDecorated, data.Decision)
	encoded, err := json.Marshal(data)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "private original")
	require.NotContains(t, string(encoded), "private input")
	require.NotContains(t, string(encoded), "private decoration")
}
