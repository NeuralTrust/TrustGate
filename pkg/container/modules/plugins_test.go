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

package modules

import (
	"io"
	"log/slog"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPluginRegistry(t *testing.T) appplugins.Registry {
	t.Helper()
	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().RedisClient().Return(nil)

	reg, err := newPluginRegistry(pluginParams{
		Cache:    cacheClient,
		Adapters: adapter.NewRegistry(),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cfg:      &config.Config{},
	})
	require.NoError(t, err)
	return reg
}

func TestNewPluginRegistry_SupportedProtocolsMatrix(t *testing.T) {
	reg := newTestPluginRegistry(t)
	want := map[string][]appplugins.Protocol{
		"request_size_limiter":  {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"rate_limiter":          {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"trustguard":            {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"per_tool_rate_limiter": {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"token_rate_limiter":    {appplugins.ProtocolLLM},
		"model_allowlist":       {appplugins.ProtocolLLM},
		"prompt_template":       {appplugins.ProtocolLLM},
		"tool_injection":        {appplugins.ProtocolLLM},
		"tool_allowlist":        {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"openai_moderation":     {appplugins.ProtocolLLM},
		"bedrock_guardrail":     {appplugins.ProtocolLLM},
		"azure_content_safety":  {appplugins.ProtocolLLM},
		"semantic_cache":        {appplugins.ProtocolLLM},
	}
	for slug, protocols := range want {
		p, ok := reg.Get(slug)
		require.Truef(t, ok, "plugin %q not registered", slug)
		assert.ElementsMatchf(t, protocols, p.SupportedProtocols(), "slug %q protocol set", slug)
		assert.NotContainsf(t, p.SupportedProtocols(), appplugins.ProtocolA2A, "slug %q must not report A2A", slug)
	}
}

func TestNewPluginRegistry_RegistersOpenAIModeration(t *testing.T) {
	reg := newTestPluginRegistry(t)

	plugin, ok := reg.Get(openaimoderation.PluginName)
	require.Truef(t, ok, "plugin %q is not registered", openaimoderation.PluginName)
	assert.Equal(t, openaimoderation.PluginName, plugin.Name())
	assert.Contains(t, reg.Names(), openaimoderation.PluginName)
}

func TestNewPluginRegistry_OpenAIModerationCatalogMetadata(t *testing.T) {
	reg := newTestPluginRegistry(t)

	catalog := appplugins.NewCatalogService(reg).Catalog()

	var entry appplugins.CatalogEntry
	groupType := ""
	found := false
	for _, group := range catalog.Groups {
		for _, item := range group.Items {
			if item.Slug == openaimoderation.PluginName {
				entry = item
				groupType = group.Type
				found = true
			}
		}
	}

	require.Truef(t, found, "catalog has no entry for %q", openaimoderation.PluginName)
	assert.Equal(t, "Guardrails", groupType)
	assert.NotEmpty(t, entry.Name)
	assert.NotEmpty(t, entry.Description)
	assert.NotEmpty(t, entry.SettingsSchema.Fields)
	assert.NotEmpty(t, entry.SupportedStages)
	assert.NotEmpty(t, entry.SupportedModes)

	keys := make([]string, 0, len(entry.SettingsSchema.Fields))
	for _, f := range entry.SettingsSchema.Fields {
		keys = append(keys, f.Key)
	}
	assert.ElementsMatch(t, []string{"api_key", "on_error", "model", "stages", "categories", "thresholds", "block_on_flagged", "action"}, keys)
}

// TestNewPluginRegistry_ContentReaderSet pins which plugins the planner
// sequences after same-priority rewriters (RUN-1693). Opting a plugin in
// changes where it runs relative to rewriters, so it must be a conscious edit
// here as well as in the plugin.
func TestNewPluginRegistry_ContentReaderSet(t *testing.T) {
	reg := newTestPluginRegistry(t)
	var got []string
	for _, name := range reg.Names() {
		p, ok := reg.Get(name)
		require.True(t, ok)
		if appplugins.IsContentReader(p) {
			got = append(got, name)
		}
	}
	assert.ElementsMatch(t, []string{"azure_content_safety", "openai_moderation", "semantic_cache"}, got)
}

// TestNewPluginRegistry_LocalRewriterSet pins which rewriters the planner runs
// ahead of the same-priority rewriters that send content to a third party
// (RUN-1745). A plugin listed here must never send the body it rewrites off the
// box: opting in a remote guard would hand it the text a local mask hides.
func TestNewPluginRegistry_LocalRewriterSet(t *testing.T) {
	reg := newTestPluginRegistry(t)
	var got []string
	for _, name := range reg.Names() {
		p, ok := reg.Get(name)
		require.True(t, ok)
		if appplugins.RewritesLocally(p) {
			got = append(got, name)
		}
	}
	assert.ElementsMatch(t, []string{
		"model_allowlist",
		"per_tool_rate_limiter",
		"prompt_compression",
		"prompt_template",
		"regex_replace",
		"token_rate_limiter",
		"tool_allowlist",
		"tool_injection",
	}, got)
}

// TestNewPluginRegistry_NativeBedrockBehaviours pins what each plugin does on a
// native Amazon Bedrock Runtime call. Every plugin not listed runs and is refused
// if it changes the bytes of the call, so adding a plugin that masks or that
// transforms the request must be a conscious edit here as well as in the plugin.
// The plugins that mask are exactly the ones that carry the on_mask_failure
// setting in the catalog.
func TestNewPluginRegistry_NativeBedrockBehaviours(t *testing.T) {
	reg := newTestPluginRegistry(t)
	want := map[string]appplugins.BedrockNativeBehavior{
		"prompt_template":    appplugins.BedrockNativeSkips,
		"tool_injection":     appplugins.BedrockNativeSkips,
		"prompt_compression": appplugins.BedrockNativeSkips,
		"semantic_cache":     appplugins.BedrockNativeSkips,
		"regex_replace":      appplugins.BedrockNativeMasks,
		"trustguard":         appplugins.BedrockNativeMasks,
		"bedrock_guardrail":  appplugins.BedrockNativeMasks,
		"google_model_armor": appplugins.BedrockNativeMasks,
	}
	got := map[string]appplugins.BedrockNativeBehavior{}
	for _, name := range reg.Names() {
		p, ok := reg.Get(name)
		require.True(t, ok)
		if behavior := appplugins.BedrockNativeOf(p); behavior != appplugins.BedrockNativeRuns {
			got[name] = behavior
		}
	}
	assert.Equal(t, want, got)

	catalog := appplugins.NewCatalogService(reg).Catalog()
	carriers := map[string]bool{}
	for _, group := range catalog.Groups {
		for _, item := range group.Items {
			for _, f := range item.SettingsSchema.Fields {
				if f.Key == appplugins.SettingOnMaskFailure {
					carriers[item.Slug] = true
					assert.Equal(t, appplugins.FieldTypeEnum, f.Type)
					assert.Equal(t, string(appplugins.MaskFailurePass), f.Default)
				}
			}
		}
	}
	for slug, behavior := range want {
		assert.Equal(t, behavior == appplugins.BedrockNativeMasks, carriers[slug], "%s: on_mask_failure belongs to the plugins that mask", slug)
		if behavior == appplugins.BedrockNativeMasks {
			err := reg.Validate(slug, map[string]any{appplugins.SettingOnMaskFailure: "Block"})
			require.Error(t, err, "%s: an invalid on_mask_failure must be refused", slug)
			assert.Contains(t, err.Error(), appplugins.SettingOnMaskFailure)
		}
	}
}

// TestNewPluginRegistry_StreamInspectorsRefuseANewStreamingOptOut pins that
// every plugin inspecting streamed responses block by block refuses a new
// streaming.enabled: false and keeps a policy stored with it editable
// (RUN-1661). A new StreamInspector must be added to the fixtures here, which is
// what makes the rule a conscious edit for it.
func TestNewPluginRegistry_StreamInspectorsRefuseANewStreamingOptOut(t *testing.T) {
	reg := newTestPluginRegistry(t)
	fixtures := map[string]func() map[string]any{
		"trustguard": func() map[string]any {
			return map[string]any{"collector_id": "11111111-1111-4111-8111-111111111111"}
		},
		"openai_moderation": func() map[string]any {
			return map[string]any{"api_key": "k", "thresholds": map[string]any{"hate": 0.7}}
		},
		"bedrock_guardrail": func() map[string]any {
			return map[string]any{
				"guardrail_id": "gr-1",
				"credentials":  map[string]any{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret"},
			}
		},
		"google_model_armor": func() map[string]any {
			return map[string]any{"project": "proj", "location": "us-central1", "template": "tmpl-1"}
		},
		"regex_replace": func() map[string]any {
			return map[string]any{
				"target": "response",
				"rules":  []map[string]any{{"pattern": "a", "replacement": "b"}},
			}
		},
	}

	var inspectors []string
	for _, name := range reg.Names() {
		p, ok := reg.Get(name)
		require.True(t, ok)
		if _, ok := p.(appplugins.StreamInspector); ok {
			inspectors = append(inspectors, name)
		}
	}
	keys := make([]string, 0, len(fixtures))
	for slug := range fixtures {
		keys = append(keys, slug)
	}
	require.ElementsMatch(t, keys, inspectors, "every StreamInspector needs a fixture here")

	withEnabled := func(set map[string]any, v any) map[string]any {
		set["streaming"] = map[string]any{"enabled": v}
		return set
	}
	for slug, base := range fixtures {
		require.NoError(t, reg.ValidateSettingsWrite(slug, base(), nil), "%s: the fixture must be a valid write", slug)

		err := reg.ValidateSettingsWrite(slug, withEnabled(base(), false), nil)
		require.Error(t, err, "%s: a new streaming.enabled: false must be refused", slug)
		assert.Contains(t, err.Error(), "streaming.enabled cannot turn it off", slug)

		assert.NoError(t, reg.ValidateSettingsWrite(slug, withEnabled(base(), false), withEnabled(base(), false)),
			"%s: a policy stored with streaming.enabled: false stays editable", slug)
		assert.NoError(t, reg.ValidateSettingsWrite(slug, withEnabled(base(), true), nil), slug)
	}
}
