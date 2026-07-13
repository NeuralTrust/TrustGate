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
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/promptdecorator"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/prompttemplate"
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

func TestNewPluginRegistry_PromptManagementPlugins(t *testing.T) {
	reg := newTestPluginRegistry(t)
	assert.Equal(t, []string{
		"azure_content_safety",
		"bedrock_guardrail",
		"cors",
		"cost_cap",
		"model_allowlist",
		"openai_moderation",
		"per_tool_rate_limiter",
		"prompt_decorator",
		"prompt_template",
		"rate_limiter",
		"request_size_limiter",
		"semantic_cache",
		"token_rate_limiter",
		"tool_allowlist",
		"tool_call_validation",
		"tool_definition_transformation",
		"trustguard",
	}, reg.Names())

	decorator, ok := reg.Get(promptdecorator.PluginName)
	require.True(t, ok)
	assert.IsType(t, &promptdecorator.Plugin{}, decorator)
	assert.Equal(t, promptdecorator.PluginName, decorator.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, decorator.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, decorator.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, decorator.SupportedModes())
	assert.True(t, decorator.MutatesRequestBody())
	assert.False(t, decorator.MutatesResponseBody())
	assert.False(t, decorator.MutatesMetadata())

	template, ok := reg.Get(prompttemplate.PluginName)
	require.True(t, ok)
	assert.IsType(t, &prompttemplate.Plugin{}, template)
	assert.Equal(t, prompttemplate.PluginName, template.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, template.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, template.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, template.SupportedModes())
	assert.True(t, template.MutatesRequestBody())
	assert.False(t, template.MutatesResponseBody())
	assert.False(t, template.MutatesMetadata())
	require.NoError(t, template.ValidateConfig(map[string]any{
		"inject_templates": []any{map[string]any{"id": "t1", "content": "unchanged"}},
	}))

	entries := make(map[string]appplugins.CatalogEntry)
	for _, group := range appplugins.NewCatalogService(reg).Catalog().Groups {
		for _, entry := range group.Items {
			entries[entry.Slug] = entry
		}
	}

	decoratorEntry, ok := entries[promptdecorator.PluginName]
	require.True(t, ok)
	assert.Equal(t, "Prompt Decorator", decoratorEntry.Name)
	assert.Equal(t, "Apply ordered static prompt decorators and optionally require an original system message. Scope is informational; effective scope is policy-owned.", decoratorEntry.Description)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, decoratorEntry.SupportedStages)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, decoratorEntry.SupportedModes)
	require.Len(t, decoratorEntry.SettingsSchema.Fields, 3)

	templateEntry, ok := entries[prompttemplate.PluginName]
	require.True(t, ok)
	assert.Equal(t, "Prompt Template", templateEntry.Name)
	assert.Equal(t, "Inject context-bound system prompts (Mode A) and/or render client-referenced named, versioned templates (Mode B) into the request before it reaches the model.", templateEntry.Description)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, templateEntry.SupportedStages)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, templateEntry.SupportedModes)
	require.Len(t, templateEntry.SettingsSchema.Fields, 9)
}

func TestNewPluginRegistry_PromptDecoratorValidation(t *testing.T) {
	reg := newTestPluginRegistry(t)
	valid := []map[string]any{
		{"require_system_message": true},
		{
			"scope": "consumer",
			"decorators": []any{
				map[string]any{"position": "start", "role": "user", "content": "context"},
			},
		},
		{
			"scope": "global",
			"decorators": []any{
				map[string]any{
					"position":           "system",
					"role":               "system",
					"content":            "guardrail",
					"on_existing_system": "append",
				},
			},
		},
	}
	for _, settings := range valid {
		require.NoError(t, reg.Validate(promptdecorator.PluginName, settings))
	}

	invalid := []map[string]any{
		{},
		{"unknown": true},
		{
			"decorators": []any{
				map[string]any{"position": "system", "role": "system", "content": "guardrail"},
			},
		},
		{
			"decorators": []any{
				map[string]any{"position": "start", "role": "system", "content": "guardrail"},
			},
		},
		{
			"decorators": []any{
				map[string]any{
					"position":           "end",
					"role":               "assistant",
					"content":            "guardrail",
					"on_existing_system": "merge",
				},
			},
		},
	}
	for _, settings := range invalid {
		require.Error(t, reg.Validate(promptdecorator.PluginName, settings))
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
