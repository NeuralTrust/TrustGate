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

package prompttemplate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/prompttemplate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func previewService(t *testing.T) appplugins.PreviewService {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(prompttemplate.New()))
	return appplugins.NewPreviewService(reg)
}

func TestPluginOptsIntoPreview(t *testing.T) {
	t.Parallel()
	var p any = prompttemplate.New()
	previewable, ok := p.(appplugins.Previewable)
	require.True(t, ok, "prompt_template must implement Previewable")
	assert.True(t, previewable.Previewable())
}

// The console's whole reason for the preview: show the operator the rendered
// system prompt before any real traffic depends on it.
func TestPreviewRendersTheSystemPromptFromAHeader(t *testing.T) {
	t.Parallel()

	got, err := previewService(t).Preview(context.Background(), appplugins.PreviewInput{
		Slug: prompttemplate.PluginName,
		Settings: map[string]any{
			"context_variables": map[string]any{
				"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
			},
			"inject_templates": []any{map[string]any{
				"id":      "safety-policy",
				"content": "You serve tenant {{tenant}}.",
			}},
		},
		Body:    []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Headers: map[string][]string{"X-Tenant-Id": {"acme"}},
	})

	require.NoError(t, err)
	assert.Equal(t, appplugins.PreviewRewritten, got.Decision)

	var body struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(got.RequestBody, &body))
	require.Len(t, body.Messages, 2)
	assert.Equal(t, "system", body.Messages[0].Role)
	assert.Equal(t, "You serve tenant acme.", body.Messages[0].Content)
}

// The misconfiguration RUN-1640 is about: a placeholder with no resolvable
// source. The preview surfaces it as a rejection instead of it reaching traffic.
func TestPreviewSurfacesAnUnresolvedVariableAsARejection(t *testing.T) {
	t.Parallel()

	got, err := previewService(t).Preview(context.Background(), appplugins.PreviewInput{
		Slug: prompttemplate.PluginName,
		Settings: map[string]any{
			"inject_templates": []any{map[string]any{
				"id":      "t1",
				"content": "Context: {{user_context}}.",
			}},
			"on_missing_context_variable": "error",
		},
		Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	})

	require.NoError(t, err)
	assert.Equal(t, appplugins.PreviewRejected, got.Decision)
	assert.Equal(t, http.StatusBadRequest, got.Status)
	assert.Contains(t, got.Message, "user_context")
}

func TestPreviewRejectsSettingsThePluginWouldNotAccept(t *testing.T) {
	t.Parallel()

	_, err := previewService(t).Preview(context.Background(), appplugins.PreviewInput{
		Slug:     prompttemplate.PluginName,
		Settings: map[string]any{"inject_templates": []any{}},
		Body:     []byte(`{"messages":[]}`),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one of inject_templates or named_templates")
}
