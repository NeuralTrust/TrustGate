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

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/require"
)

func pluginDecoratorSettings(content string) map[string]any {
	return map[string]any{
		"decorators": []any{
			map[string]any{
				"position": "end",
				"role":     "assistant",
				"content":  content,
			},
		},
	}
}

func pluginInput(mode policy.Mode, sourceFormat string, body, originalBody []byte, settings map[string]any) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage: policy.StagePreRequest,
		Mode:  mode,
		Config: policy.PluginConfig{
			ID:       "prompt-decorator-test",
			Slug:     PluginName,
			Name:     PluginName,
			Settings: settings,
		},
		Request: &infracontext.RequestContext{
			SourceFormat: sourceFormat,
			Body:         body,
			OriginalBody: originalBody,
		},
	}
}

func pluginEvent() (*metrics.EventContext, *trace.Span) {
	tr := trace.New("", trace.Metadata{})
	span := tr.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func TestPluginDescriptor(t *testing.T) {
	t.Parallel()

	plugin := New()
	require.Equal(t, PluginName, plugin.Name())
	require.Equal(t, []policy.Stage{policy.StagePreRequest}, plugin.MandatoryStages())
	require.Equal(t, []policy.Stage{policy.StagePreRequest}, plugin.SupportedStages())
	require.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, plugin.SupportedModes())
	require.True(t, plugin.MutatesRequestBody())
	require.False(t, plugin.MutatesResponseBody())
	require.False(t, plugin.MutatesMetadata())
}

func TestPluginValidateConfigDelegatesToStrictParser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid decorator",
			settings: pluginDecoratorSettings("safe"),
		},
		{
			name:     "valid require only",
			settings: map[string]any{"require_system_message": true},
		},
		{
			name:     "empty configuration",
			settings: map[string]any{},
			wantErr:  true,
		},
		{
			name:     "unknown field",
			settings: map[string]any{"require_system_message": true, "unknown": true},
			wantErr:  true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := New().ValidateConfig(test.settings)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
