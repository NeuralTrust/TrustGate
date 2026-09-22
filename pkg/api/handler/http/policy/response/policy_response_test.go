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

package response_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/azurecontentsafety"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/bedrockguardrail"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/googlemodelarmor"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/semanticcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryWithCredentialPlugins registers the five real, production plugin
// types declared in RUN-1646. Their CredentialPaths() implementations do not
// touch any struct field, so the zero value is safe to register and use here
// without constructing any of their infra dependencies (HTTP clients, caches,
// adapters).
func registryWithCredentialPlugins(t *testing.T) appplugins.Registry {
	t.Helper()
	reg := appplugins.NewRegistry()
	for _, p := range []appplugins.Plugin{
		&bedrockguardrail.Plugin{},
		&googlemodelarmor.Plugin{},
		&azurecontentsafety.Plugin{},
		&openaimoderation.Plugin{},
		&semanticcache.Plugin{},
	} {
		require.NoError(t, reg.Register(p))
	}
	return reg
}

func policyWithSettings(t *testing.T, slug string, settings map[string]any) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(ids.New[ids.GatewayKind](), "name", slug, true, 0, false, settings, nil, "", domain.ModeEnforce, nil)
	require.NoError(t, err)
	return p
}

func TestFromPolicy_MasksEachDeclaredCredentialPlugin(t *testing.T) {
	t.Parallel()
	reg := registryWithCredentialPlugins(t)

	cases := []struct {
		slug     string
		settings map[string]any
		assert   func(t *testing.T, settings map[string]any)
	}{
		{
			slug: "bedrock_guardrail",
			settings: map[string]any{
				"guardrail_id": "gr-1",
				"credentials": map[string]any{
					"access_key_id":     "AKIAREALVALUE",
					"secret_access_key": "sk-supersecretvalue1234",
					"session_token":     "sess-token-value-123456",
				},
			},
			assert: func(t *testing.T, out map[string]any) {
				creds := out["credentials"].(map[string]any)
				assert.NotEqual(t, "AKIAREALVALUE", creds["access_key_id"])
				assert.True(t, secret.IsMasked(creds["access_key_id"].(string)))
				assert.True(t, secret.IsMasked(creds["secret_access_key"].(string)))
				assert.True(t, secret.IsMasked(creds["session_token"].(string)))
			},
		},
		{
			slug: "google_model_armor",
			settings: map[string]any{
				"project": "p", "location": "us-central1", "template": "t",
				"credentials": map[string]any{"service_account_json": `{"type":"service_account","private_key":"secretvalue1234"}`},
			},
			assert: func(t *testing.T, out map[string]any) {
				creds := out["credentials"].(map[string]any)
				assert.True(t, secret.IsMasked(creds["service_account_json"].(string)))
			},
		},
		{
			slug: "azure_content_safety",
			settings: map[string]any{
				"api_key": "az-supersecretvalue1234", "endpoint": "https://example.cognitiveservices.azure.com",
			},
			assert: func(t *testing.T, out map[string]any) {
				assert.True(t, secret.IsMasked(out["api_key"].(string)))
			},
		},
		{
			slug: "openai_moderation",
			settings: map[string]any{
				"api_key": "sk-supersecretvalue1234",
			},
			assert: func(t *testing.T, out map[string]any) {
				assert.True(t, secret.IsMasked(out["api_key"].(string)))
			},
		},
		{
			slug: "semantic_cache",
			settings: map[string]any{
				"embedding": map[string]any{"provider": "openai", "model": "text-embedding-ada-002", "api_key": "sk-supersecretvalue1234"},
			},
			assert: func(t *testing.T, out map[string]any) {
				emb := out["embedding"].(map[string]any)
				assert.True(t, secret.IsMasked(emb["api_key"].(string)))
				assert.Equal(t, "openai", emb["provider"], "sibling field must survive untouched")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.slug, func(t *testing.T) {
			p := policyWithSettings(t, tc.slug, tc.settings)
			out := response.FromPolicy(p, reg)
			tc.assert(t, out.Settings)
		})
	}
}

// This is the aliasing bug RUN-1646 warned about: p.Settings is the very map
// app/plugins/plan.go hands to plugin execution. If FromPolicy's masking
// mutated it, every guardrail call after the first rendered response would
// receive the mask instead of the real credential.
func TestFromPolicy_DoesNotMutateThePolicysSettingsMap(t *testing.T) {
	t.Parallel()
	reg := registryWithCredentialPlugins(t)
	p := policyWithSettings(t, "bedrock_guardrail", map[string]any{
		"guardrail_id": "gr-1",
		"credentials": map[string]any{
			"access_key_id":     "AKIAREALVALUE",
			"secret_access_key": "sk-supersecretvalue1234",
		},
	})

	out := response.FromPolicy(p, reg)

	require.True(t, secret.IsMasked(out.Settings["credentials"].(map[string]any)["access_key_id"].(string)),
		"sanity: the response must actually be masked")

	creds := p.Settings["credentials"].(map[string]any)
	assert.Equal(t, "AKIAREALVALUE", creds["access_key_id"],
		"p.Settings (what plan.go hands to plugin execution) must still carry the real credential")
	assert.Equal(t, "sk-supersecretvalue1234", creds["secret_access_key"],
		"p.Settings (what plan.go hands to plugin execution) must still carry the real credential")
}

// A plugin that never declared credential paths (every plugin besides the
// five above) must be returned byte-for-byte as stored: no masking applies.
func TestFromPolicy_PluginWithoutDeclaredPathsIsUnaffected(t *testing.T) {
	t.Parallel()
	reg := registryWithCredentialPlugins(t) // rate_limiter is not registered here at all
	p := policyWithSettings(t, "rate_limiter", map[string]any{"limit": 100})

	out := response.FromPolicy(p, reg)

	assert.Same(t, &p.Settings, &p.Settings) // sanity the field exists
	assert.Equal(t, p.Settings, out.Settings)
	assert.Equal(t, 100, out.Settings["limit"])
}

func TestFromPolicy_NilRegistryIsSafe(t *testing.T) {
	t.Parallel()
	p := policyWithSettings(t, "bedrock_guardrail", map[string]any{
		"credentials": map[string]any{"access_key_id": "AKIAREALVALUE"},
	})
	out := response.FromPolicy(p, nil)
	assert.Equal(t, "AKIAREALVALUE", out.Settings["credentials"].(map[string]any)["access_key_id"],
		"without a registry there is no plugin schema to mask by, same as an unaffected plugin")
}
