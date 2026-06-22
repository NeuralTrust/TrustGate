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
	"semantic_cache",
	"model_allowlist",
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
		{"semantic_cache", []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}, []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}},
		{"model_allowlist", []policy.Stage{policy.StagePreRequest}, []policy.Stage{policy.StagePreRequest}},
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
	assert.Equal(t, []string{groupTrafficControl, groupQuota, groupRouting}, types)

	byType := make(map[string][]string)
	for _, g := range catalog.Groups {
		for _, item := range g.Items {
			byType[g.Type] = append(byType[g.Type], item.Slug)
		}
	}
	assert.ElementsMatch(t, []string{"rate_limiter", "request_size_limiter", "cors"}, byType[groupTrafficControl])
	assert.Equal(t, []string{"token_rate_limiter"}, byType[groupQuota])
	assert.ElementsMatch(t, []string{"semantic_cache", "model_allowlist", "tool_allowlist"}, byType[groupRouting])
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
	assert.Equal(t, "Token & Dollar Budget + Cost Cap", meta.name)
	assert.Contains(t, meta.description, "cost cap")

	fields := meta.schema.Fields

	unit, ok := fieldByKey(fields, "unit")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, unit.Type)
	assert.Equal(t, []string{"tokens", "dollars"}, unit.Enum)

	perModel, ok := fieldByKey(fields, "per_model")
	require.True(t, ok)
	assert.Equal(t, FieldTypeBoolean, perModel.Type)

	counting, ok := fieldByKey(fields, "counting")
	require.True(t, ok)
	assert.Equal(t, []string{"total", "input", "output"}, counting.Enum)

	behavior, ok := fieldByKey(fields, "behavior_on_exceeded")
	require.True(t, ok)
	assert.Equal(t, FieldTypeEnum, behavior.Type)
	assert.Equal(t, []string{"reject", "throttle", "downgrade_model", "alert_only"}, behavior.Enum)
	assert.Contains(t, behavior.Enum, "alert_only")

	pricingTable, ok := fieldByKey(fields, "pricing_table")
	require.True(t, ok)
	assert.Equal(t, []string{"builtin", "custom"}, pricingTable.Enum)

	for _, k := range []string{"downgrade_to", "stream_usage_injection", "count_cache_reads", "group_by_header"} {
		_, ok := fieldByKey(fields, k)
		assert.Truef(t, ok, "missing top-level field %q", k)
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

func TestTokenRateLimiterSchema_CostCapAndPricingMaps(t *testing.T) {
	fields := pluginCatalogMeta["token_rate_limiter"].schema.Fields

	costCap, ok := fieldByKey(fields, "cost_cap")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, costCap.Type)

	behaviorOnViolation, ok := fieldByKey(costCap.Fields, "behavior_on_violation")
	require.True(t, ok)
	assert.Equal(t, []string{"reject", "downgrade"}, behaviorOnViolation.Enum)

	unknownModel, ok := fieldByKey(costCap.Fields, "unknown_model")
	require.True(t, ok)
	assert.Equal(t, []string{"reject", "pass_through", "assume_max"}, unknownModel.Enum)

	overrides, ok := fieldByKey(costCap.Fields, "per_model_overrides")
	require.True(t, ok)
	assert.Equal(t, FieldTypeMap, overrides.Type)
	require.NotNil(t, overrides.Value)
	assert.Equal(t, FieldTypeObject, overrides.Value.Type)
	for _, k := range []string{"max_input_cost_per_1k_tokens", "max_output_cost_per_1k_tokens"} {
		_, ok := fieldByKey(overrides.Value.Fields, k)
		assert.Truef(t, ok, "override missing %q", k)
	}

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

func TestTokenRateLimiterSchema_LegacyWindowPreserved(t *testing.T) {
	fields := pluginCatalogMeta["token_rate_limiter"].schema.Fields

	window, ok := fieldByKey(fields, "window")
	require.True(t, ok)
	assert.Equal(t, FieldTypeObject, window.Type)
	assert.False(t, window.Required)

	unit, ok := fieldByKey(window.Fields, "unit")
	require.True(t, ok)
	assert.Equal(t, []string{"second", "minute", "hour", "day"}, unit.Enum)

	_, ok = fieldByKey(window.Fields, "max")
	assert.True(t, ok)
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
