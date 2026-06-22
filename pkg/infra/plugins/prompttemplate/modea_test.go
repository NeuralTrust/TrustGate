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
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func modeAConfig(t *testing.T, onMissing onMissingContext, templates []injectTemplate) *config {
	t.Helper()
	cfg := &config{
		TemplateEngine:           engineMustache,
		OnMissingContextVariable: onMissing,
		OnMissingClientVariable:  onMissingClientError,
		InjectTemplates:          templates,
	}
	cfg.applyDefaults()
	return cfg
}

func TestApplyModeAInjection(t *testing.T) {
	t.Run("merge into existing system message", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextError, []injectTemplate{
			{ID: "a", Position: "system", Role: roleSystem, Content: "support for {{tenant}}", OnExistingSystem: onExistingMerge},
		})
		rb, err := decodeBody([]byte(`{"messages":[{"role":"system","content":"Be concise."}]}`))
		require.NoError(t, err)
		outcome := applyModeA(cfg, rb, map[string]string{"tenant": "acme"})
		assert.True(t, outcome.changed)
		assert.Equal(t, []string{"a"}, outcome.injected)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"Be concise.\n\nsupport for acme"}]}`, string(out))
	})

	t.Run("replace existing system string", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextError, []injectTemplate{
			{ID: "a", Position: "system", Role: roleSystem, Content: "fresh", OnExistingSystem: onExistingReplace},
		})
		rb, err := decodeBody([]byte(`{"system":"old"}`))
		require.NoError(t, err)
		applyModeA(cfg, rb, nil)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"system":"fresh"}`, string(out))
	})

	t.Run("multiple inject entries apply in order", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextError, []injectTemplate{
			{ID: "a", Position: "system", Role: roleSystem, Content: "first", OnExistingSystem: onExistingMerge},
			{ID: "b", Position: "system", Role: roleSystem, Content: "second", OnExistingSystem: onExistingMerge},
		})
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		outcome := applyModeA(cfg, rb, nil)
		assert.Equal(t, []string{"a", "b"}, outcome.injected)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"first\n\nsecond"},{"role":"user","content":"hi"}]}`, string(out))
	})
}

func TestApplyModeAPreservesMessages(t *testing.T) {
	cfg := modeAConfig(t, onMissingContextError, []injectTemplate{
		{ID: "a", Position: "system", Role: roleSystem, Content: "support for {{tenant}}", OnExistingSystem: onExistingMerge},
	})
	raw := []byte(`{"messages":[` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]},` +
		`{"role":"user","content":[{"type":"text","text":"hi"}],"name":"alice"}` +
		`]}`)
	rb, err := decodeBody(raw)
	require.NoError(t, err)
	outcome := applyModeA(cfg, rb, map[string]string{"tenant": "acme"})
	assert.True(t, outcome.changed)
	out, err := rb.marshal()
	require.NoError(t, err)
	assert.JSONEq(t, `{"messages":[`+
		`{"role":"system","content":"support for acme"},`+
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{}"}}]},`+
		`{"role":"user","content":[{"type":"text","text":"hi"}],"name":"alice"}`+
		`]}`, string(out))
}

func TestApplyModeAMissingPolicies(t *testing.T) {
	t.Run("error collects unresolved", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextError, []injectTemplate{
			{ID: "a", Position: "system", Role: roleSystem, Content: "for {{tenant}}", OnExistingSystem: onExistingMerge},
		})
		rb, err := decodeBody([]byte(`{"messages":[]}`))
		require.NoError(t, err)
		outcome := applyModeA(cfg, rb, nil)
		assert.False(t, outcome.changed)
		assert.Equal(t, []string{"tenant"}, outcome.unresolved)
	})

	t.Run("empty_string substitutes blank", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextEmptyString, []injectTemplate{
			{ID: "a", Position: "system", Role: roleSystem, Content: "for {{tenant}}", OnExistingSystem: onExistingMerge},
		})
		rb, err := decodeBody([]byte(`{"messages":[]}`))
		require.NoError(t, err)
		outcome := applyModeA(cfg, rb, nil)
		assert.True(t, outcome.changed)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"for "}]}`, string(out))
	})

	t.Run("skip_injection drops missing entry but keeps others", func(t *testing.T) {
		cfg := modeAConfig(t, onMissingContextSkip, []injectTemplate{
			{ID: "a", Position: "system", Role: roleSystem, Content: "for {{tenant}}", OnExistingSystem: onExistingMerge},
			{ID: "b", Position: "system", Role: roleSystem, Content: "always", OnExistingSystem: onExistingMerge},
		})
		rb, err := decodeBody([]byte(`{"messages":[]}`))
		require.NoError(t, err)
		outcome := applyModeA(cfg, rb, nil)
		assert.Equal(t, []string{"a"}, outcome.skipped)
		assert.Equal(t, []string{"b"}, outcome.injected)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"always"}]}`, string(out))
	})
}

func execSettings() map[string]any {
	return map[string]any{
		"context_variables": map[string]any{
			"tenant": map[string]any{"source": "header", "name": "X-Tenant-Id"},
		},
		"inject_templates": []any{
			map[string]any{
				"id":                 "a",
				"position":           "system",
				"role":               "system",
				"content":            "support for {{tenant}}",
				"on_existing_system": "merge",
			},
		},
		"on_missing_context_variable": "error",
	}
}

func TestExecuteNilRequest(t *testing.T) {
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: execSettings()},
		Request: nil,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody)
}

func TestExecuteEnforceInjects(t *testing.T) {
	req := &infracontext.RequestContext{
		Headers: map[string][]string{"X-Tenant-Id": {"acme"}},
		Body:    []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: execSettings()},
		Request: req,
	})
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	assert.JSONEq(t, `{"messages":[{"role":"system","content":"support for acme"},{"role":"user","content":"hi"}]}`, string(res.RequestBody))
}

func TestExecuteEnforceUnresolvedRejects(t *testing.T) {
	req := &infracontext.RequestContext{
		Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
	}
	_, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeEnforce,
		Config:  policy.PluginConfig{Settings: execSettings()},
		Request: req,
	})
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusInternalServerError, pe.StatusCode)
	assert.Equal(t, typeVariableUnresolved, pe.Type)
}

func TestExecuteObserveDoesNotMutateOrReject(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	req := &infracontext.RequestContext{Body: body}
	res, err := New().Execute(context.Background(), appplugins.ExecInput{
		Mode:    policy.ModeObserve,
		Config:  policy.PluginConfig{Settings: execSettings()},
		Request: req,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.RequestBody)
	assert.Equal(t, `{"messages":[{"role":"user","content":"hi"}]}`, string(req.Body))
}
