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

package prompttemplate

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Contract(t *testing.T) {
	t.Parallel()

	p := New()

	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, "prompt_template", p.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
	assert.Contains(t, p.SupportedModes(), policy.ModeEnforce)
	assert.Contains(t, p.SupportedModes(), policy.ModeObserve)
}

func TestPlugin_ExecuteNoOp(t *testing.T) {
	t.Parallel()

	res, err := New().Execute(context.Background(), appplugins.ExecInput{Mode: policy.ModeEnforce})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody)
	assert.Nil(t, res.Body)
}

func TestErrorTypeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "template_variable_unresolved", typeVariableUnresolved)
	assert.Equal(t, "template_variable_missing", typeVariableMissing)
	assert.Equal(t, "template_variable_invalid", typeVariableInvalid)
	assert.Equal(t, "template_not_found", typeNotFound)
	assert.Equal(t, "template_required", typeRequired)
}

func TestVarSourceConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, varSource("header"), sourceHeader)
	assert.Equal(t, varSource("jwt_claim"), sourceJWTClaim)
}

func modeBSettings(allowUntemplated bool) map[string]any {
	return map[string]any{
		"named_templates": []any{
			map[string]any{
				"name": "support-bot",
				"versions": []any{
					map[string]any{
						"version": "v3",
						"labels":  []any{"stable"},
						"content": `[{"role":"system","content":"You are a {{persona}} bot."}]`,
						"required_variables": map[string]any{
							"persona": map[string]any{"type": "string", "enum": []any{"friendly", "formal"}},
						},
					},
				},
			},
		},
		"default_label":              "stable",
		"allow_untemplated_requests": allowUntemplated,
	}
}

func TestExecuteModeBRenders(t *testing.T) {
	req := &infracontext.RequestContext{
		Body: []byte(`{"model":"gpt-4","properties":{"persona":"friendly"},"messages":[{"role":"user","content":"{template://support-bot@stable}"}]}`),
	}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: modeBSettings(false)},
		Request: req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	assert.JSONEq(t, `{"model":"gpt-4","messages":[{"role":"system","content":"You are a friendly bot."}]}`, string(res.RequestBody))

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(res.RequestBody, &got))
	_, hasProps := got["properties"]
	assert.False(t, hasProps)
}

func TestExecuteModeBMissingVariable(t *testing.T) {
	req := &infracontext.RequestContext{
		Body: []byte(`{"messages":[{"role":"user","content":"{template://support-bot@stable}"}]}`),
	}
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: modeBSettings(false)},
		Request: req,
	})
	pe := requirePluginError(t, err)
	assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
	assert.Equal(t, typeVariableMissing, pe.Type)
}

func TestExecuteModeBInvalidVariable(t *testing.T) {
	req := &infracontext.RequestContext{
		Body: []byte(`{"properties":{"persona":"rude"},"messages":[{"role":"user","content":"{template://support-bot@stable}"}]}`),
	}
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: modeBSettings(false)},
		Request: req,
	})
	pe := requirePluginError(t, err)
	assert.Equal(t, typeVariableInvalid, pe.Type)
}

func TestExecuteModeBTemplateRequired(t *testing.T) {
	req := &infracontext.RequestContext{
		Body: []byte(`{"messages":[{"role":"user","content":"plain text"}]}`),
	}
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: modeBSettings(false)},
		Request: req,
	})
	pe := requirePluginError(t, err)
	assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
	assert.Equal(t, typeRequired, pe.Type)
}

func TestExecuteModeBPassthroughStripsProperties(t *testing.T) {
	req := &infracontext.RequestContext{
		Body: []byte(`{"properties":{"persona":"friendly"},"messages":[{"role":"user","content":"plain"}]}`),
	}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: modeBSettings(true)},
		Request: req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	assert.JSONEq(t, `{"messages":[{"role":"user","content":"plain"}]}`, string(res.RequestBody))
}

func TestExecuteModeBObserveNoMutationNoReject(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"{template://nope}"}]}`)
	req := &infracontext.RequestContext{Body: body}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeObserve,
		Config:  policy.PluginConfig{Settings: modeBSettings(false)},
		Request: req,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody)
	assert.Equal(t, `{"messages":[{"role":"user","content":"{template://nope}"}]}`, string(req.Body))
}

func TestExecuteModeAOnlyStripsProperties(t *testing.T) {
	req := &infracontext.RequestContext{
		Headers: map[string][]string{"X-Tenant-Id": {"acme"}},
		Body:    []byte(`{"properties":{"x":"y"},"messages":[{"role":"user","content":"hi"}]}`),
	}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: execSettings()},
		Request: req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	assert.JSONEq(t, `{"messages":[{"role":"system","content":"support for acme"},{"role":"user","content":"hi"}]}`, string(res.RequestBody))

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(res.RequestBody, &got))
	_, hasProps := got["properties"]
	assert.False(t, hasProps)
}

func TestExecuteObserveStripsPropertiesOnly(t *testing.T) {
	req := &infracontext.RequestContext{
		Headers: map[string][]string{"X-Tenant-Id": {"acme"}},
		Body:    []byte(`{"properties":{"x":"y"},"messages":[{"role":"user","content":"hi"}]}`),
	}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeObserve,
		Config:  policy.PluginConfig{Settings: execSettings()},
		Request: req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	assert.JSONEq(t, `{"messages":[{"role":"user","content":"hi"}]}`, string(res.RequestBody))
}

func TestExecuteModeAAndModeB(t *testing.T) {
	settings := modeBSettings(false)
	settings["context_variables"] = map[string]any{
		"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
	}
	settings["inject_templates"] = []any{
		map[string]any{
			"id": "a", "position": "system", "role": "system",
			"content": "tenant {{tenant}}", "on_existing_system": "merge",
		},
	}
	settings["on_missing_context_variable"] = "error"

	req := &infracontext.RequestContext{
		Headers: map[string][]string{"X-Tenant-Id": {"acme"}},
		Body:    []byte(`{"properties":{"persona":"friendly"},"messages":[{"role":"user","content":"{template://support-bot@stable}"}]}`),
	}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: settings},
		Request: req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	assert.JSONEq(t, `{"messages":[{"role":"system","content":"You are a friendly bot.\n\ntenant acme"}]}`, string(res.RequestBody))
}
