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

package tokenratelimit

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func usageResponseBody() []byte {
	return []byte(`{"id":"x","model":"m","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
}

func TestPlugin_PerModel_IsolatesBudgets(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"per_model": true,
		"rules": []map[string]any{
			{"model": "model-a", "max": 10, "time_window": "1m"},
			{"model": "model-b", "max": 10, "time_window": "1m"},
		},
	}
	reqA := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-a"}`)}
	reqB := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-b"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqA, &infracontext.ResponseContext{}))
	require.Error(t, err, "model-a is over its own budget")
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqB, &infracontext.ResponseContext{}))
	require.NoError(t, err, "model-b keeps an independent budget")
}

func TestPlugin_PerModel_HeadersReflectBreachedWindow(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"per_model": true,
		"rules":     []map[string]any{{"model": "model-a", "max": 5, "time_window": "1m"}},
		"aggregate": map[string]any{"max": 1000, "time_window": "1m"},
	}
	reqA := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-a"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)

	_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, reqA, &infracontext.ResponseContext{}))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
	assert.Equal(t, []string{"5"}, pe.Headers["X-Ratelimit-Limit-Tokens"],
		"headers must reflect the breached per-model window (max 5), not the aggregate (max 1000)")
	assert.Equal(t, []string{"0"}, pe.Headers["X-Ratelimit-Remaining-Tokens"])
}

func TestPlugin_PerModel_CountingOutput(t *testing.T) {
	p := newTestPlugin(t)
	settings := map[string]any{
		"per_model": true,
		"counting":  "output",
		"rules": []map[string]any{
			{"model": "model-a", "max": 6, "time_window": "1m"},
		},
	}
	reqA := &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(`{"model":"model-a"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: usageResponseBody()}

	res, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, reqA, resp))
	require.NoError(t, err)
	assert.Equal(t, []string{"5"}, res.Headers["X-Tokens-Consumed"], "only output tokens are counted")
}
