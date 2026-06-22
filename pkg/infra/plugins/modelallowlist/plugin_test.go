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

package modelallowlist

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func input(mode policy.Mode, settings map[string]any, req *infracontext.RequestContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    policy.StagePreRequest,
		Mode:     mode,
		Config:   policy.PluginConfig{ID: "ma-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request:  req,
		Response: &infracontext.ResponseContext{},
	}
}

func TestPlugin_StagesModesName(t *testing.T) {
	p := New()
	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	p := New()
	require.NoError(t, p.ValidateConfig(map[string]any{"allowed_models": []string{"gpt-5*"}}))
	require.Error(t, p.ValidateConfig(map[string]any{"allowed_models": []string{}}))
}

func TestPlugin_Execute(t *testing.T) {
	rejectGPT5 := map[string]any{"allowed_models": []string{"gpt-5*"}, "behavior_on_disallowed": "reject"}
	substituteGPT5 := map[string]any{
		"allowed_models":         []string{"gpt-5*"},
		"behavior_on_disallowed": "substitute",
		"substitute_with":        "gpt-5",
	}
	defaultGPT5 := map[string]any{"allowed_models": []string{"gpt-5*"}, "default_model": "gpt-5"}

	tests := []struct {
		name       string
		mode       policy.Mode
		settings   map[string]any
		nilRequest bool
		body       string
		check      func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext)
	}{
		{
			name:     "exact allow",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allowed_models": []string{"gpt-4o"}},
			body:     `{"model":"gpt-4o"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.False(t, res.StopUpstream)
				assert.JSONEq(t, `{"model":"gpt-4o"}`, string(req.Body))
			},
		},
		{
			name:     "glob allow prefix",
			mode:     policy.ModeEnforce,
			settings: rejectGPT5,
			body:     `{"model":"gpt-5-mini"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.JSONEq(t, `{"model":"gpt-5-mini"}`, string(req.Body))
			},
		},
		{
			name:     "glob allow suffix",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allowed_models": []string{"*sonnet*"}},
			body:     `{"model":"claude-sonnet-4"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.JSONEq(t, `{"model":"claude-sonnet-4"}`, string(req.Body))
			},
		},
		{
			name:     "disallowed reject body",
			mode:     policy.ModeEnforce,
			settings: rejectGPT5,
			body:     `{"model":"gpt-3.5"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, 403, res.StatusCode)
				assert.True(t, res.StopUpstream)
				assert.Equal(t, []string{"application/json"}, res.Headers["Content-Type"])
				assert.Equal(t, `{"error":{"type":"model_not_allowed","model":"gpt-3.5","allowed":["gpt-5*"]}}`, string(res.Body))
			},
		},
		{
			name:     "disallowed substitute rewrites body",
			mode:     policy.ModeEnforce,
			settings: substituteGPT5,
			body:     `{"model":"gpt-3.5"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.False(t, res.StopUpstream)
				require.NotNil(t, res.RequestBody)
				model, mErr := adapter.ExtractModel(res.RequestBody)
				require.NoError(t, mErr)
				assert.Equal(t, "gpt-5", model)
				assert.JSONEq(t, `{"model":"gpt-3.5"}`, string(req.Body))
			},
		},
		{
			name:     "default injection on absent model",
			mode:     policy.ModeEnforce,
			settings: defaultGPT5,
			body:     `{"messages":[]}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				require.NotNil(t, res.RequestBody)
				model, mErr := adapter.ExtractModel(res.RequestBody)
				require.NoError(t, mErr)
				assert.Equal(t, "gpt-5", model)
				assert.JSONEq(t, `{"messages":[]}`, string(req.Body))
			},
		},
		{
			name:     "absent model no default is no-op",
			mode:     policy.ModeEnforce,
			settings: rejectGPT5,
			body:     `{"messages":[]}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.JSONEq(t, `{"messages":[]}`, string(req.Body))
			},
		},
		{
			name:     "observe disallowed reject never blocks",
			mode:     policy.ModeObserve,
			settings: rejectGPT5,
			body:     `{"model":"gpt-3.5"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.False(t, res.StopUpstream)
				assert.JSONEq(t, `{"model":"gpt-3.5"}`, string(req.Body))
			},
		},
		{
			name:     "observe disallowed substitute never mutates",
			mode:     policy.ModeObserve,
			settings: substituteGPT5,
			body:     `{"model":"gpt-3.5"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.JSONEq(t, `{"model":"gpt-3.5"}`, string(req.Body))
			},
		},
		{
			name:     "observe absent default never mutates",
			mode:     policy.ModeObserve,
			settings: defaultGPT5,
			body:     `{"messages":[]}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.JSONEq(t, `{"messages":[]}`, string(req.Body))
			},
		},
		{
			name:     "malformed body is no-op allow",
			mode:     policy.ModeEnforce,
			settings: rejectGPT5,
			body:     `not json`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.False(t, res.StopUpstream)
				assert.Equal(t, "not json", string(req.Body))
			},
		},
		{
			name:     "malformed body with default is no-op allow",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}, "default_model": "gpt-5"},
			body:     `not json`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.False(t, res.StopUpstream)
				assert.Equal(t, "not json", string(req.Body))
			},
		},
		{
			name:     "bedrock modelId substitute rewrites",
			mode:     policy.ModeEnforce,
			settings: substituteGPT5,
			body:     `{"modelId":"anthropic.claude"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				require.NotNil(t, res.RequestBody)
				model, mErr := adapter.ExtractModel(res.RequestBody)
				require.NoError(t, mErr)
				assert.Equal(t, "gpt-5", model)
			},
		},
		{
			name:     "bedrock modelId allowed pass through",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allowed_models": []string{"arn:aws:bedrock:*"}},
			body:     `{"modelId":"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
				assert.JSONEq(t, `{"modelId":"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude"}`, string(req.Body))
			},
		},
		{
			name:       "nil request is no-op",
			mode:       policy.ModeEnforce,
			settings:   rejectGPT5,
			nilRequest: true,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, 200, res.StatusCode)
			},
		},
		{
			name:     "bad config returns error",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allowed_models": []string{}},
			body:     `{"model":"gpt-4o"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.Error(t, err)
				assert.Nil(t, res)
			},
		},
		{
			name:     "arn literal exact allow",
			mode:     policy.ModeEnforce,
			settings: map[string]any{"allowed_models": []string{"arn:aws:bedrock:us-east-1::foundation-model/claude"}},
			body:     `{"model":"arn:aws:bedrock:us-east-1::foundation-model/claude"}`,
			check: func(t *testing.T, res *appplugins.Result, err error, req *infracontext.RequestContext) {
				require.NoError(t, err)
				assert.Equal(t, 200, res.StatusCode)
			},
		},
	}

	p := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *infracontext.RequestContext
			if !tt.nilRequest {
				req = &infracontext.RequestContext{Body: []byte(tt.body)}
			}
			res, err := p.Execute(context.Background(), input(tt.mode, tt.settings, req))
			tt.check(t, res, err, req)
		})
	}
}
