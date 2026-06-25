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

package plugins

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// builtinSlugs are the slugs registered by the production plugin module. The
// test uses string literals (not the infra plugin constants) to avoid an import
// cycle, since infra plugins depend on this package.
var builtinSlugs = []string{
	"rate_limiter",
	"request_size_limiter",
	"cors",
	"token_rate_limiter",
	"cost_cap",
	"semantic_cache",
	"model_allowlist",
	"prompt_template",
	"tool_allowlist",
}

func registerBuiltins(t *testing.T) Registry {
	t.Helper()
	reg := NewRegistry()
	specs := []struct {
		name      string
		mandatory []policy.Stage
		supported []policy.Stage
	}{
		{"rate_limiter", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
		{"request_size_limiter", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
		{"cors", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
		{"token_rate_limiter", []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}},
		{"cost_cap", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
		{"semantic_cache", []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}},
		{"model_allowlist", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
		{"prompt_template", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
		{"tool_allowlist", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
	}
	for _, s := range specs {
		require.NoError(t, reg.Register(&stagePlugin{name: s.name, mandatory: s.mandatory, supported: s.supported}))
	}
	return reg
}

func TestCatalogService_GroupsAndOrder(t *testing.T) {
	svc := NewCatalogService(registerBuiltins(t))
	catalog := svc.Catalog()

	types := make([]string, 0, len(catalog.Groups))
	for _, g := range catalog.Groups {
		types = append(types, g.Type)
	}
	assert.Equal(t, []string{groupTrafficControl, groupQuota, groupRouting, groupPromptManagement}, types)

	byType := make(map[string][]string)
	for _, g := range catalog.Groups {
		for _, item := range g.Items {
			byType[g.Type] = append(byType[g.Type], item.Slug)
		}
	}
	assert.ElementsMatch(t, []string{"rate_limiter", "request_size_limiter", "cors"}, byType[groupTrafficControl])
	assert.ElementsMatch(t, []string{"token_rate_limiter", "cost_cap"}, byType[groupQuota])
	assert.ElementsMatch(t, []string{"semantic_cache", "model_allowlist", "tool_allowlist"}, byType[groupRouting])
	assert.Equal(t, []string{"prompt_template"}, byType[groupPromptManagement])
}

func TestCatalogService_EntriesHaveStagesAndSchema(t *testing.T) {
	svc := NewCatalogService(registerBuiltins(t))
	catalog := svc.Catalog()

	entries := make(map[string]CatalogEntry)
	for _, g := range catalog.Groups {
		for _, item := range g.Items {
			entries[item.Slug] = item
		}
	}

	require.Len(t, entries, len(builtinSlugs))
	for _, slug := range builtinSlugs {
		entry, ok := entries[slug]
		require.Truef(t, ok, "slug %q missing from catalog", slug)
		assert.NotEmptyf(t, entry.Name, "slug %q has empty display name", slug)
		assert.NotEmptyf(t, entry.SupportedStages, "slug %q has no supported stages", slug)
		assert.NotEmptyf(t, entry.SettingsSchema.Fields, "slug %q has no settings schema fields", slug)
		assert.NotEmptyf(t, entry.SupportedModes, "slug %q has no supported modes", slug)
		assert.Containsf(t, entry.SupportedModes, policy.ModeEnforce, "slug %q must support enforce", slug)
		assert.Equalf(t, policy.DefaultMode, entry.DefaultMode, "slug %q default mode mismatch", slug)
	}

	// Stage data must come from the plugin implementation, not the metadata.
	assert.Equal(t,
		[]policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		entries["token_rate_limiter"].SupportedStages,
	)
}

func TestCatalogService_OnlyRegisteredPlugins(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&stagePlugin{
		name:      "rate_limiter",
		mandatory: []policy.Stage{policy.StagePreRequest},
		supported: []policy.Stage{policy.StagePreRequest},
	}))

	catalog := NewCatalogService(reg).Catalog()
	require.Len(t, catalog.Groups, 1)
	assert.Equal(t, groupTrafficControl, catalog.Groups[0].Type)
	require.Len(t, catalog.Groups[0].Items, 1)
	assert.Equal(t, "rate_limiter", catalog.Groups[0].Items[0].Slug)
}

func TestCatalogService_UnknownPluginFallsBackToOther(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&stagePlugin{
		name:      "mystery",
		mandatory: []policy.Stage{policy.StagePreRequest},
		supported: []policy.Stage{policy.StagePreRequest},
	}))

	catalog := NewCatalogService(reg).Catalog()
	require.Len(t, catalog.Groups, 1)
	assert.Equal(t, groupOther, catalog.Groups[0].Type)
	require.Len(t, catalog.Groups[0].Items, 1)
	entry := catalog.Groups[0].Items[0]
	assert.Equal(t, "mystery", entry.Slug)
	assert.Equal(t, "mystery", entry.Name)
}

func fieldByKey(fields []Field, key string) (Field, bool) {
	for _, f := range fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

func TestTokenRateLimiterSchema_BudgetTree(t *testing.T) {
	meta, ok := pluginCatalogMeta["token_rate_limiter"]
	require.True(t, ok)
	assert.Equal(t, "LLM Budget", meta.name)
	assert.Contains(t, meta.description, "budget")

	fields := meta.schema.Fields

	unit, ok := fieldByKey(fields, "unit")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, unit.Type)
	assert.Equal(t, []string{"tokens", "dollars"}, unit.Enum)

	counting, ok := fieldByKey(fields, "counting")
	require.True(t, ok)
	assert.Equal(t, []string{"total", "input", "output"}, counting.Enum)

	behavior, ok := fieldByKey(fields, "behavior_on_exceeded")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, behavior.Type)
	assert.Equal(t, []string{"reject", "throttle", "downgrade_model", "alert_only"}, behavior.Enum)
	assert.Contains(t, behavior.Enum, "alert_only")

	for _, k := range []string{"downgrade_to", "stream_usage_injection", "count_cache_reads", "custom_pricing", "group_by_header"} {
		_, ok := fieldByKey(fields, k)
		assert.Truef(t, ok, "missing top-level field %q", k)
	}

	// Cost cap, the legacy window block, per_model and pricing_table moved out
	// of the budget catalog schema even though their parsing is preserved.
	for _, k := range []string{"cost_cap", "window", "per_model", "pricing_table"} {
		_, ok := fieldByKey(fields, k)
		assert.Falsef(t, ok, "field %q must not be in the budget catalog schema", k)
	}
}

func TestTokenRateLimiterSchema_RulesAndAggregate(t *testing.T) {
	fields := pluginCatalogMeta["token_rate_limiter"].schema.Fields

	rules, ok := fieldByKey(fields, "rules")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, rules.Type)
	require.NotNil(t, rules.Item)
	assert.Equal(t, FieldTypeObject, rules.Item.Type)
	for _, k := range []string{"model", "max", "time_window"} {
		_, ok := fieldByKey(rules.Item.Fields, k)
		assert.Truef(t, ok, "rules item missing %q", k)
	}

	aggregate, ok := fieldByKey(fields, "aggregate")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, aggregate.Type)
	for _, k := range []string{"max", "time_window"} {
		_, ok := fieldByKey(aggregate.Fields, k)
		assert.Truef(t, ok, "aggregate missing %q", k)
	}
}

func TestTokenRateLimiterSchema_CustomPricingMap(t *testing.T) {
	fields := pluginCatalogMeta["token_rate_limiter"].schema.Fields

	customPricing, ok := fieldByKey(fields, "custom_pricing")
	require.True(t, ok)
	assert.Equal(t, FieldTypeMap, customPricing.Type)
	require.NotNil(t, customPricing.Value)
	assert.Equal(t, FieldTypeObject, customPricing.Value.Type)
	for _, k := range []string{"input", "output"} {
		_, ok := fieldByKey(customPricing.Value.Fields, k)
		assert.Truef(t, ok, "custom_pricing missing %q", k)
	}
}

func TestCostCapSchema(t *testing.T) {
	meta, ok := pluginCatalogMeta["cost_cap"]
	require.True(t, ok)
	assert.Equal(t, "LLM Cost Cap", meta.name)
	assert.Equal(t, groupQuota, meta.group)

	fields := meta.schema.Fields

	for _, k := range []string{"max_input_cost_per_1k_tokens", "max_output_cost_per_1k_tokens", "downgrade_to", "custom_pricing"} {
		_, ok := fieldByKey(fields, k)
		assert.Truef(t, ok, "cost_cap missing top-level field %q", k)
	}

	// The standalone cost cap has no on/off toggle; its presence enables it.
	_, ok = fieldByKey(fields, "enabled")
	assert.False(t, ok, "cost_cap must not expose an enabled toggle")

	behaviorOnViolation, ok := fieldByKey(fields, "behavior_on_violation")
	require.True(t, ok)
	assert.Equal(t, []string{"reject", "downgrade"}, behaviorOnViolation.Enum)

	unknownModel, ok := fieldByKey(fields, "unknown_model")
	require.True(t, ok)
	assert.Equal(t, []string{"reject", "pass_through", "assume_max"}, unknownModel.Enum)

	overrides, ok := fieldByKey(fields, "per_model_overrides")
	require.True(t, ok)
	assert.Equal(t, FieldTypeMap, overrides.Type)
	require.NotNil(t, overrides.Value)
	assert.Equal(t, FieldTypeObject, overrides.Value.Type)
	for _, k := range []string{"max_input_cost_per_1k_tokens", "max_output_cost_per_1k_tokens"} {
		_, ok := fieldByKey(overrides.Value.Fields, k)
		assert.Truef(t, ok, "override missing %q", k)
	}
}

func TestToolDefinitionTransformation_CatalogEntry(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&stagePlugin{
		name:      "tool_definition_transformation",
		mandatory: []policy.Stage{policy.StagePreRequest},
		supported: []policy.Stage{policy.StagePreRequest},
	}))

	catalog := NewCatalogService(reg).Catalog()
	require.Len(t, catalog.Groups, 1)
	group := catalog.Groups[0]
	assert.Equal(t, groupToolGovernance, group.Type)
	require.Len(t, group.Items, 1)

	entry := group.Items[0]
	assert.Equal(t, "tool_definition_transformation", entry.Slug)
	assert.Equal(t, "Tool Definition Transformation", entry.Name)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, entry.MandatoryStages)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, entry.SupportedStages)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce}, entry.SupportedModes)
}

func TestToolDefinitionTransformationSchema_Fields(t *testing.T) {
	meta, ok := pluginCatalogMeta["tool_definition_transformation"]
	require.True(t, ok)
	assert.Equal(t, "Tool Definition Transformation", meta.name)
	assert.Equal(t, groupToolGovernance, meta.group)

	fields := meta.schema.Fields

	transformTools, ok := fieldByKey(fields, "transform_tools")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, transformTools.Type)
	require.NotNil(t, transformTools.Item)
	assert.Equal(t, FieldTypeObject, transformTools.Item.Type)

	tool, ok := fieldByKey(transformTools.Item.Fields, "tool")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, tool.Type)
	assert.True(t, tool.Required)

	schemaPatch, ok := fieldByKey(transformTools.Item.Fields, "schema_patch")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, schemaPatch.Type)
	assert.Empty(t, schemaPatch.Fields)

	descriptionOverride, ok := fieldByKey(transformTools.Item.Fields, "description_override")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, descriptionOverride.Type)

	injectTools, ok := fieldByKey(fields, "inject_tools")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, injectTools.Type)
	require.NotNil(t, injectTools.Item)
	assert.Equal(t, FieldTypeObject, injectTools.Item.Type)

	injectType, ok := fieldByKey(injectTools.Item.Fields, "type")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, injectType.Type)
	assert.Equal(t, []string{"function"}, injectType.Enum)
	assert.Equal(t, "function", injectType.Default)

	function, ok := fieldByKey(injectTools.Item.Fields, "function")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, function.Type)

	name, ok := fieldByKey(function.Fields, "name")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, name.Type)
	assert.True(t, name.Required)

	parameters, ok := fieldByKey(function.Fields, "parameters")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, parameters.Type)
	assert.Empty(t, parameters.Fields)

	onConflict, ok := fieldByKey(fields, "on_conflict")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, onConflict.Type)
	assert.Equal(t, []string{"gateway_wins", "client_wins", "reject"}, onConflict.Enum)
	assert.Equal(t, "gateway_wins", onConflict.Default)

	scope, ok := fieldByKey(fields, "scope")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, scope.Type)
	assert.Equal(t, []string{"consumer", "global"}, scope.Enum)
}

func TestToolAllowlistSchema(t *testing.T) {
	meta, ok := pluginCatalogMeta["tool_allowlist"]
	require.True(t, ok)
	assert.Equal(t, "Tool Allowlist", meta.name)
	assert.Equal(t, groupRouting, meta.group)

	fields := meta.schema.Fields

	allow, ok := fieldByKey(fields, "allow_tools")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, allow.Type)
	require.NotNil(t, allow.Item)
	assert.Equal(t, FieldTypeString, allow.Item.Type)

	deny, ok := fieldByKey(fields, "deny_tools")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, deny.Type)
	require.NotNil(t, deny.Item)
	assert.Equal(t, FieldTypeString, deny.Item.Type)

	onEmpty, ok := fieldByKey(fields, "on_empty_after_filter")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, onEmpty.Type)
	assert.Equal(t, []string{"reject", "pass_through_empty", "strip_tools_field"}, onEmpty.Enum)
	assert.Equal(t, "reject", onEmpty.Default)

	scope, ok := fieldByKey(fields, "scope")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, scope.Type)
	assert.Equal(t, []string{"consumer", "global"}, scope.Enum)
}

func TestTrustGuardSchema(t *testing.T) {
	meta, ok := pluginCatalogMeta["trustguard"]
	require.True(t, ok)
	assert.Equal(t, "TrustGuard", meta.name)
	assert.Equal(t, groupGuardrails, meta.group)

	fields := meta.schema.Fields

	apiKey, ok := fieldByKey(fields, "api_key")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, apiKey.Type)
	assert.True(t, apiKey.Required)

	inspect, ok := fieldByKey(fields, "inspect")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, inspect.Type)
	assert.Equal(t, []string{"request", "response", "request_response"}, inspect.Enum)
	assert.Equal(t, "request_response", inspect.Default)

	baseURL, ok := fieldByKey(fields, "base_url")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, baseURL.Type)
	assert.False(t, baseURL.Required)
}

func TestSemanticCacheSchema(t *testing.T) {
	meta, ok := pluginCatalogMeta["semantic_cache"]
	require.True(t, ok)
	assert.Equal(t, "Semantic Cache", meta.name)
	assert.Equal(t, groupRouting, meta.group)

	fields := meta.schema.Fields

	mode, ok := fieldByKey(fields, "mode")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, mode.Type)
	assert.Equal(t, []string{"exact", "semantic", "both"}, mode.Enum)
	assert.Equal(t, "semantic", mode.Default)

	scope, ok := fieldByKey(fields, "scope")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, scope.Type)
	assert.Equal(t, []string{"consumer", "global"}, scope.Enum)
	assert.Equal(t, "consumer", scope.Default)

	vectorStore, ok := fieldByKey(fields, "vector_store")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, vectorStore.Type)
	assert.Equal(t, []string{"redis", "pgvector", "in_memory"}, vectorStore.Enum)
	assert.Equal(t, "redis", vectorStore.Default)

	ttlSeconds, ok := fieldByKey(fields, "ttl_seconds")
	require.True(t, ok)
	assert.Equal(t, FieldTypeInteger, ttlSeconds.Type)

	embeddingProvider, ok := fieldByKey(fields, "embedding_provider")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, embeddingProvider.Type)

	embeddingModel, ok := fieldByKey(fields, "embedding_model")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, embeddingModel.Type)

	cacheOnlyOnStatus, ok := fieldByKey(fields, "cache_only_on_status")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, cacheOnlyOnStatus.Type)
	require.NotNil(t, cacheOnlyOnStatus.Item)
	assert.Equal(t, FieldTypeInteger, cacheOnlyOnStatus.Item.Type)
	assert.Equal(t, []int{200}, cacheOnlyOnStatus.Default)

	bypassHeader, ok := fieldByKey(fields, "bypass_header")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, bypassHeader.Type)
	assert.Equal(t, "X-Cache-Bypass", bypassHeader.Default)

	skipIfTools, ok := fieldByKey(fields, "skip_if_tools_present")
	require.True(t, ok)
	assert.Equal(t, FieldTypeBoolean, skipIfTools.Type)
	assert.Equal(t, true, skipIfTools.Default)

	skipIfStreaming, ok := fieldByKey(fields, "skip_if_streaming")
	require.True(t, ok)
	assert.Equal(t, FieldTypeBoolean, skipIfStreaming.Type)
	assert.Equal(t, false, skipIfStreaming.Default)

	embedding, ok := fieldByKey(fields, "embedding")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, embedding.Type)
	assert.False(t, embedding.Required)

	apiKey, ok := fieldByKey(embedding.Fields, "api_key")
	require.True(t, ok)
	assert.False(t, apiKey.Required)

	similarityThreshold, ok := fieldByKey(fields, "similarity_threshold")
	require.True(t, ok)
	assert.Equal(t, FieldTypeNumber, similarityThreshold.Type)

	ttl, ok := fieldByKey(fields, "ttl")
	require.True(t, ok)
	assert.Equal(t, FieldTypeDuration, ttl.Type)
}

func TestPluginCatalogMeta_CoversBuiltins(t *testing.T) {
	validGroups := map[string]struct{}{}
	for _, g := range groupOrder {
		validGroups[g] = struct{}{}
	}

	for _, slug := range builtinSlugs {
		meta, ok := pluginCatalogMeta[slug]
		require.Truef(t, ok, "missing catalog metadata for slug %q", slug)
		assert.NotEmptyf(t, meta.name, "slug %q has empty name", slug)
		assert.NotEmptyf(t, meta.description, "slug %q has empty description", slug)
		_, groupOK := validGroups[meta.group]
		assert.Truef(t, groupOK, "slug %q has group %q outside groupOrder", slug, meta.group)
		assert.NotEmptyf(t, meta.schema.Fields, "slug %q has empty settings schema", slug)
		for _, f := range meta.schema.Fields {
			assert.NotEmptyf(t, f.Key, "slug %q has a field with empty key", slug)
			assert.NotEmptyf(t, f.Type, "slug %q field %q has empty type", slug, f.Key)
		}
	}
}

func TestPromptTemplate_CatalogEntry(t *testing.T) {
	svc := NewCatalogService(registerBuiltins(t))
	catalog := svc.Catalog()

	var entry CatalogEntry
	found := false
	for _, g := range catalog.Groups {
		if g.Type != groupPromptManagement {
			continue
		}
		for _, item := range g.Items {
			if item.Slug == "prompt_template" {
				entry = item
				found = true
			}
		}
	}

	require.True(t, found, "prompt_template missing from the Prompt Management group")
	assert.Equal(t, "Prompt Template", entry.Name)
	assert.Contains(t, entry.SupportedModes, policy.ModeEnforce)
	assert.Equal(t, policy.DefaultMode, entry.DefaultMode)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, entry.SupportedStages)
	assert.NotEmpty(t, entry.SettingsSchema.Fields)
}

func TestPromptTemplateSchema_Tree(t *testing.T) {
	meta, ok := pluginCatalogMeta["prompt_template"]
	require.True(t, ok)
	assert.Equal(t, "Prompt Template", meta.name)
	assert.Equal(t, groupPromptManagement, meta.group)

	fields := meta.schema.Fields

	engineField, ok := fieldByKey(fields, "template_engine")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, engineField.Type)
	assert.Equal(t, []string{"mustache", "jinja2_subset"}, engineField.Enum)
	assert.Equal(t, "mustache", engineField.Default)

	contextVars, ok := fieldByKey(fields, "context_variables")
	require.True(t, ok)
	assert.Equal(t, FieldTypeMap, contextVars.Type)
	require.NotNil(t, contextVars.Value)
	assert.Equal(t, FieldTypeObject, contextVars.Value.Type)
	source, ok := fieldByKey(contextVars.Value.Fields, "source")
	require.True(t, ok)
	assert.Equal(t, []string{"header", "jwt_claim"}, source.Enum)
	ctxName, ok := fieldByKey(contextVars.Value.Fields, "name")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, ctxName.Type)

	inject, ok := fieldByKey(fields, "inject_templates")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, inject.Type)
	require.NotNil(t, inject.Item)
	for _, k := range []string{"id", "position", "role", "content", "on_existing_system"} {
		_, ok := fieldByKey(inject.Item.Fields, k)
		assert.Truef(t, ok, "inject_templates item missing %q", k)
	}
	onExisting, ok := fieldByKey(inject.Item.Fields, "on_existing_system")
	require.True(t, ok)
	assert.Equal(t, []string{"merge", "replace"}, onExisting.Enum)

	named, ok := fieldByKey(fields, "named_templates")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, named.Type)
	require.NotNil(t, named.Item)

	nameField, ok := fieldByKey(named.Item.Fields, "name")
	require.True(t, ok)
	assert.Equal(t, FieldTypeString, nameField.Type)

	versions, ok := fieldByKey(named.Item.Fields, "versions")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, versions.Type)
	require.NotNil(t, versions.Item)
	for _, k := range []string{"version", "labels", "content", "required_variables"} {
		_, ok := fieldByKey(versions.Item.Fields, k)
		assert.Truef(t, ok, "version item missing %q", k)
	}

	labels, ok := fieldByKey(versions.Item.Fields, "labels")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, labels.Type)
	require.NotNil(t, labels.Item)
	assert.Equal(t, FieldTypeString, labels.Item.Type)

	requiredVars, ok := fieldByKey(versions.Item.Fields, "required_variables")
	require.True(t, ok)
	assert.Equal(t, FieldTypeMap, requiredVars.Type)
	require.NotNil(t, requiredVars.Value)
	assert.Equal(t, FieldTypeObject, requiredVars.Value.Type)
	rvType, ok := fieldByKey(requiredVars.Value.Fields, "type")
	require.True(t, ok)
	assert.Equal(t, []string{"string", "number", "boolean"}, rvType.Enum)

	rvEnum, ok := fieldByKey(requiredVars.Value.Fields, "enum")
	require.True(t, ok)
	assert.Equal(t, FieldTypeArray, rvEnum.Type)
	require.NotNil(t, rvEnum.Item)
	assert.Equal(t, FieldTypeString, rvEnum.Item.Type)

	rvMaxLength, ok := fieldByKey(requiredVars.Value.Fields, "max_length")
	require.True(t, ok)
	assert.Equal(t, FieldTypeInteger, rvMaxLength.Type)

	onMissingContext, ok := fieldByKey(fields, "on_missing_context_variable")
	require.True(t, ok)
	assert.Equal(t, []string{"error", "empty_string", "skip_injection"}, onMissingContext.Enum)

	onMissingClient, ok := fieldByKey(fields, "on_missing_client_variable")
	require.True(t, ok)
	assert.Equal(t, []string{"error", "empty_string"}, onMissingClient.Enum)

	for _, k := range []string{"allow_untemplated_requests", "default_label", "escape_json_control_chars"} {
		_, ok := fieldByKey(fields, k)
		assert.Truef(t, ok, "missing top-level field %q", k)
	}
}
