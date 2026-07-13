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

package adapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/promptdecorator"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/require"
)

type translatedMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func TestPromptDecoratorAnthropicMergeTranslatesWithoutExtraNewline(t *testing.T) {
	systemRepresentations := map[string]string{
		"string": `"Base"`,
		"blocks": `[{"type":"text","text":"Base","cache_control":{"type":"ephemeral"}}]`,
	}
	targets := map[string]string{
		"Claude":            "anthropic.claude-3-5-sonnet-20241022-v2:0",
		"OpenAI-compatible": "us.deepseek.deepseek-r1-v1:0",
	}

	for representation, system := range systemRepresentations {
		for target, model := range targets {
			t.Run(representation+"/"+target, func(t *testing.T) {
				body := []byte(fmt.Sprintf(
					`{"model":%q,"system":%s,"messages":[{"role":"user","content":"Question"},{"role":"assistant","content":"Answer"},{"role":"user","content":"Follow-up"}],"max_tokens":128}`,
					model,
					system,
				))
				result, err := promptdecorator.New().Execute(
					context.Background(),
					appplugins.ExecInput{
						Stage: policy.StagePreRequest,
						Mode:  policy.ModeEnforce,
						Config: policy.PluginConfig{Settings: map[string]any{
							"decorators": []any{map[string]any{
								"role":               "system",
								"content":            "Decorated",
								"position":           "system",
								"on_existing_system": "merge",
							}},
						}},
						Request: &infracontext.RequestContext{
							Body:         body,
							OriginalBody: bytes.Clone(body),
							SourceFormat: string(adapter.FormatAnthropic),
						},
					},
				)
				require.NoError(t, err)
				require.NotNil(t, result)

				output, err := adapter.NewRegistry().AdaptRequest(
					result.RequestBody,
					adapter.FormatAnthropic,
					adapter.FormatBedrock,
				)
				require.NoError(t, err)

				var request struct {
					System   string              `json:"system"`
					Messages []translatedMessage `json:"messages"`
				}
				require.NoError(t, json.Unmarshal(output, &request))
				if target == "Claude" {
					require.Equal(t, "Base\n\nDecorated", request.System)
					require.Len(t, request.Messages, 3)
					require.Equal(t, []string{"user", "assistant", "user"}, messageRoles(request.Messages))
					return
				}

				require.Empty(t, request.System)
				require.Len(t, request.Messages, 4)
				require.Equal(
					t,
					[]string{"system", "user", "assistant", "user"},
					messageRoles(request.Messages),
				)
				require.JSONEq(t, `"Base\n\nDecorated"`, string(request.Messages[0].Content))
			})
		}
	}
}

func messageRoles(messages []translatedMessage) []string {
	roles := make([]string, len(messages))
	for i := range messages {
		roles[i] = messages[i].Role
	}
	return roles
}
