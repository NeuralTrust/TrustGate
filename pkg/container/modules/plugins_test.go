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
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tool_call_validation"
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
		"cors":                           {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"request_size_limiter":           {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"rate_limiter":                   {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"trustguard":                     {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"per_tool_rate_limiter":          {appplugins.ProtocolLLM, appplugins.ProtocolMCP},
		"cost_cap":                       {appplugins.ProtocolLLM},
		"token_rate_limiter":             {appplugins.ProtocolLLM},
		"model_allowlist":                {appplugins.ProtocolLLM},
		"prompt_template":                {appplugins.ProtocolLLM},
		"tool_definition_transformation": {appplugins.ProtocolLLM},
		"tool_allowlist":                 {appplugins.ProtocolLLM},
		"tool_call_validation":           {appplugins.ProtocolLLM},
		"openai_moderation":              {appplugins.ProtocolLLM},
		"bedrock_guardrail":              {appplugins.ProtocolLLM},
		"azure_content_safety":           {appplugins.ProtocolLLM},
		"semantic_cache":                 {appplugins.ProtocolLLM},
	}
	for slug, protocols := range want {
		p, ok := reg.Get(slug)
		require.Truef(t, ok, "plugin %q not registered", slug)
		assert.ElementsMatchf(t, protocols, p.SupportedProtocols(), "slug %q protocol set", slug)
		assert.NotContainsf(t, p.SupportedProtocols(), appplugins.ProtocolA2A, "slug %q must not report A2A", slug)
	}
}

func TestNewPluginRegistry_RegistersToolCallValidation(t *testing.T) {
	reg := newTestPluginRegistry(t)

	plugin, ok := reg.Get(tool_call_validation.PluginName)
	require.Truef(t, ok, "plugin %q is not registered", tool_call_validation.PluginName)
	assert.Equal(t, tool_call_validation.PluginName, plugin.Name())
	assert.Contains(t, reg.Names(), tool_call_validation.PluginName)
}

func TestNewPluginRegistry_ToolCallValidationCatalogMetadata(t *testing.T) {
	reg := newTestPluginRegistry(t)

	catalog := appplugins.NewCatalogService(reg).Catalog()

	var entry appplugins.CatalogEntry
	found := false
	for _, group := range catalog.Groups {
		for _, item := range group.Items {
			if item.Slug == tool_call_validation.PluginName {
				entry = item
				found = true
			}
		}
	}

	require.Truef(t, found, "catalog has no entry for %q", tool_call_validation.PluginName)
	assert.NotEmpty(t, entry.Name)
	assert.NotEmpty(t, entry.Description)
	assert.NotEmpty(t, entry.SettingsSchema.Fields)
	assert.NotEmpty(t, entry.SupportedStages)
	assert.NotEmpty(t, entry.SupportedModes)

	keys := make([]string, 0, len(entry.SettingsSchema.Fields))
	for _, f := range entry.SettingsSchema.Fields {
		keys = append(keys, f.Key)
	}
	assert.ElementsMatch(t, []string{"scope", "semantic", "rules"}, keys)
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
	assert.ElementsMatch(t, []string{"api_key", "model", "stages", "categories", "thresholds", "block_on_flagged", "action"}, keys)
}
