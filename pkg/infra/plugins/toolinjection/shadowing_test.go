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

package toolinjection

import (
	"context"
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	legacyShadow = `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],` +
		`"functions":[{"name":"safety_check","description":"client"},{"name":"other"}],"function_call":{"name":"safety_check"}}`
	twiceShadow = `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[` +
		`{"type":"function","function":{"name":"safety_check","description":"client one"}},` +
		`{"type":"function","function":{"name":"safety_check","description":"client two"}}]}`
)

func TestPluginGatewayWinsOverAClientCopyOfItsTool(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"a legacy function": legacyShadow, "a tool declared twice": twiceShadow} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			res := execPreRequest(t, injectSettings(), string(adapter.FormatOpenAI), []byte(body))

			out := string(res.RequestBody)
			assert.NotContains(t, out, `"client`, out)
			assert.Equal(t, 1, strings.Count(out, `"safety_check"`), out)
			assert.NotContains(t, out, `"function_call"`, out)
			if body == legacyShadow {
				assert.Contains(t, out, `"functions":[{"name":"other"}]`, out)
			}
		})
	}
}

func TestPluginClientWinsKeepsItsLegacyFunction(t *testing.T) {
	t.Parallel()
	settings := injectSettings()
	settings["on_conflict"] = conflictClientWins
	p := New(adapter.NewRegistry())
	res, err := p.Execute(context.Background(), preRequestInput(settings, legacyShadow))
	require.NoError(t, err)
	assert.Nil(t, res.RequestBody)
}

func TestPluginRejectsALegacyFunctionNamedLikeItsTool(t *testing.T) {
	t.Parallel()
	settings := injectSettings()
	settings["on_conflict"] = conflictReject
	_, err := New(adapter.NewRegistry()).Execute(context.Background(), preRequestInput(settings, legacyShadow))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "err = %v", err)
	assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
}

func preRequestInput(settings map[string]any, body string) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:   policy.StagePreRequest,
		Config:  policy.PluginConfig{ID: "ti-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request: &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: []byte(body)},
	}
}

func TestApplyInjectionsKeepsTheCacheMarkerOfADroppedCopy(t *testing.T) {
	t.Parallel()
	marker := &adapter.CanonicalCacheBreakpoint{TTL: "1h"}
	tools := []adapter.CanonicalTool{
		{Name: "safety_check", Description: "client one"},
		{Name: "other"},
		{Name: "safety_check", Description: "client two", Cache: marker},
	}
	entries := []injectDef{{Type: "function", Function: fnDef{Name: "safety_check", Description: "gateway"}}}

	out, _, err := applyInjections(tools, entries, conflictGatewayWins)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, "gateway", out[0].Description)
	assert.Same(t, marker, out[0].Cache)
	assert.Nil(t, out[1].Cache)
}
