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

package docs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type openAPIOperation struct {
	Description string `json:"description"`
	Parameters  []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	} `json:"parameters"`
	RequestBody struct {
		Content map[string]openAPIMediaType `json:"content"`
	} `json:"requestBody"`
	Responses map[string]struct {
		Description string                      `json:"description"`
		Content     map[string]openAPIMediaType `json:"content"`
	} `json:"responses"`
}

type openAPIMediaType struct {
	Schema struct {
		Ref string `json:"$ref"`
	} `json:"schema"`
}

type openAPISchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
}

type openAPIDocument struct {
	Paths map[string]struct {
		Get    openAPIOperation `json:"get"`
		Post   openAPIOperation `json:"post"`
		Put    openAPIOperation `json:"put"`
		Delete openAPIOperation `json:"delete"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]openAPISchema `json:"schemas"`
	} `json:"components"`
}

func loadOpenAPIDocument(t *testing.T) openAPIDocument {
	t.Helper()
	raw, err := os.ReadFile("openapi.json")
	require.NoError(t, err)

	var document openAPIDocument
	require.NoError(t, json.Unmarshal(raw, &document))
	return document
}

func schemaByRef(t *testing.T, document openAPIDocument, ref string) openAPISchema {
	t.Helper()
	name := strings.TrimPrefix(ref, "#/components/schemas/")
	require.NotEmpty(t, name, "missing schema reference")
	schema, ok := document.Components.Schemas[name]
	require.True(t, ok, "schema %s not found", name)
	return schema
}

func TestRegistryListOpenAPIDocumentsFlatAndGroupedShapes(t *testing.T) {
	document := loadOpenAPIDocument(t)

	operation, ok := document.Paths["/v1/gateways/{gateway_id}/registries"]
	require.True(t, ok)
	assert.Contains(t, operation.Get.Description, "two mutually exclusive variants")
	assert.Contains(t, operation.Get.Description, "at most 200 total registries")

	success, ok := operation.Get.Responses["200"]
	require.True(t, ok)
	assert.Contains(t, success.Description, "flat (items/page/size/total)")
	assert.Contains(t, success.Description, "grouped (view/groups/total_groups/total_instances)")
	mediaType, ok := success.Content["application/json"]
	require.True(t, ok)
	schema := schemaByRef(t, document, mediaType.Schema.Ref)

	for _, field := range []string{
		"items",
		"page",
		"size",
		"total",
		"view",
		"groups",
		"total_groups",
		"total_instances",
	} {
		assert.Contains(t, schema.Properties, field)
	}
}

func TestPolicyOpenAPIDocumentsMCPScopeAndWarnings(t *testing.T) {
	document := loadOpenAPIDocument(t)

	collection, ok := document.Paths["/v1/gateways/{gateway_id}/policies"]
	require.True(t, ok)
	item, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}"]
	require.True(t, ok)

	createBody, ok := collection.Post.RequestBody.Content["application/json"]
	require.True(t, ok)
	createSchema := schemaByRef(t, document, createBody.Schema.Ref)
	assert.Contains(t, createSchema.Properties, "mcp_scope")
	scopeSchema := schemaByRef(t, document, refOf(t, createSchema.Properties["mcp_scope"]))
	for _, field := range []string{"registry_ids", "tools", "groups", "except_groups"} {
		assert.Contains(t, scopeSchema.Properties, field)
	}
	for _, field := range []string{"users", "except_users"} {
		assert.NotContains(t, scopeSchema.Properties, field, "the user dimension is retired and must stay out of the contract")
	}

	updateBody, ok := item.Put.RequestBody.Content["application/json"]
	require.True(t, ok)
	updateSchema := schemaByRef(t, document, updateBody.Schema.Ref)
	assert.Contains(t, updateSchema.Properties, "mcp_scope")
	assert.Contains(t, item.Put.Description, "null clears it")

	created, ok := collection.Post.Responses["201"]
	require.True(t, ok)
	responseBody, ok := created.Content["application/json"]
	require.True(t, ok)
	responseSchema := schemaByRef(t, document, responseBody.Schema.Ref)
	assert.Contains(t, responseSchema.Properties, "mcp_scope")
	assert.Contains(t, responseSchema.Properties, "warnings")

	var hasRegistryFilter bool
	for _, parameter := range collection.Get.Parameters {
		if parameter.Name == "registry_id" && parameter.In == "query" {
			hasRegistryFilter = true
		}
	}
	assert.True(t, hasRegistryFilter, "GET policies must document the registry_id query filter")

	attach, ok := document.Paths["/v1/gateways/{gateway_id}/consumers/{id}/policies/{policy_id}"]
	require.True(t, ok)
	_, ok = attach.Post.Responses["204"]
	assert.True(t, ok, "attach without warnings stays 204")
	warned, ok := attach.Post.Responses["200"]
	require.True(t, ok, "attach with warnings answers 200")
	warnedBody, ok := warned.Content["application/json"]
	require.True(t, ok)
	assert.Contains(t, schemaByRef(t, document, warnedBody.Schema.Ref).Properties, "warnings")
}

// The level rule (RUN-1621, rule 3) surfaces as a 409 on the write paths that
// can take a level. Create is not one of them: a new policy is attached to no
// consumer and not global, so it holds no level and its 409 stays the name
// clash. The test pins that asymmetry, because a 409 documented on create
// would tell an operator to look for a conflict the guard cannot raise there.
func TestPolicyOpenAPIDocumentsLevelConflictOnTheWritesThatTakeALevel(t *testing.T) {
	document := loadOpenAPIDocument(t)

	item, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}"]
	require.True(t, ok)
	assert.Contains(t, item.Put.Description, "level another policy of the same plugin already holds")
	assert.Contains(t, item.Put.Description, "turning enabled back on",
		"enabling is the write the rule would otherwise be sidestepped by")
	updateConflict, ok := item.Put.Responses["409"]
	require.True(t, ok, "update must document the level conflict")
	assert.Contains(t, updateConflict.Description, "already runs this plugin at one of the levels")

	promote, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}/global"]
	require.True(t, ok)
	promoteConflict, ok := promote.Post.Responses["409"]
	require.True(t, ok, "promotion must document the level conflict")
	assert.Contains(t, promoteConflict.Description, "all-traffic level")

	attach, ok := document.Paths["/v1/gateways/{gateway_id}/consumers/{id}/policies/{policy_id}"]
	require.True(t, ok)
	attachConflict, ok := attach.Post.Responses["409"]
	require.True(t, ok, "attach must document the level conflict")
	assert.Contains(t, attachConflict.Description, "already runs this plugin at one of the levels")

	collection, ok := document.Paths["/v1/gateways/{gateway_id}/policies"]
	require.True(t, ok)
	createConflict, ok := collection.Post.Responses["409"]
	require.True(t, ok)
	assert.NotContains(t, createConflict.Description, "level",
		"a created policy is a draft and takes no level, so its 409 is the name clash alone")
	assert.Contains(t, collection.Post.Description, "runs nowhere and holds no level until it is attached or promoted")
}

// The MCP-wide placement mirrors /global: promoting takes the all-consumers
// levels and can be refused, demoting only releases levels and never is. The
// schema only proves mcp_wide is a property; that every response carries it,
// false included, is pinned by policy_response_test.go.
func TestPolicyOpenAPIDocumentsTheMCPWidePlacement(t *testing.T) {
	document := loadOpenAPIDocument(t)

	placement, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}/mcp-wide"]
	require.True(t, ok, "the MCP-wide placement must be documented")

	for _, status := range []string{"200", "404", "409", "422"} {
		_, ok := placement.Post.Responses[status]
		assert.True(t, ok, "POST /mcp-wide must document %s", status)
	}
	assert.Contains(t, placement.Post.Responses["409"].Description, "already runs this plugin at one of the levels")
	assert.Contains(t, placement.Post.Responses["409"].Description, "changed while it was being promoted")
	assert.Contains(t, placement.Post.Responses["422"].Description, "does not support MCP")
	assert.Contains(t, placement.Post.Description, "never runs on LLM or A2A consumers")
	assert.Contains(t, placement.Post.Description, "removes the policy's consumer links in the same write")
	assert.Contains(t, placement.Post.Description, "already MCP-wide answers 200")
	assert.Contains(t, placement.Delete.Description, "holds no consumer links")

	for _, status := range []string{"200", "404"} {
		_, ok := placement.Delete.Responses[status]
		assert.True(t, ok, "DELETE /mcp-wide must document %s", status)
	}
	for _, status := range []string{"409", "422"} {
		_, ok := placement.Delete.Responses[status]
		assert.False(t, ok, "demoting releases levels, so DELETE /mcp-wide never answers %s", status)
	}

	promoted, ok := placement.Post.Responses["200"].Content["application/json"]
	require.True(t, ok)
	schema := schemaByRef(t, document, promoted.Schema.Ref)
	assert.Contains(t, schema.Properties, "mcp_wide")
	assert.Contains(t, schema.Properties, "global")
	assert.Contains(t, schema.Properties, "warnings")

	global, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}/global"]
	require.True(t, ok)
	assert.Contains(t, global.Post.Description, "clears mcp_wide")
	assert.Contains(t, global.Post.Responses["409"].Description, "changed while it was being promoted")
	assert.Contains(t, global.Post.Description, "already global by then, which answers 200")
	assert.Contains(t, global.Delete.Description, "Clears only global")

	item, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}"]
	require.True(t, ok)
	updateInvalid, ok := item.Put.Responses["422"]
	require.True(t, ok, "a slug change of an MCP-wide policy to a plugin without MCP support answers 422")
	assert.Contains(t, updateInvalid.Description, "without MCP support")

	duplicate, ok := document.Paths["/v1/gateways/{gateway_id}/policies/{id}/duplicate"]
	require.True(t, ok)
	assert.Contains(t, duplicate.Post.Description, "neither global nor MCP-wide")
}

// Rule 2 opened the attach of a group-only scope to a non-MCP consumer, so the
// description may no longer promise that a scoped policy is MCP-only. An
// MCP-wide policy holds no links, so the attach also documents refusing it.
func TestAttachPolicyOpenAPIDescribesTheGroupOnlyScopeAsAttachable(t *testing.T) {
	document := loadOpenAPIDocument(t)

	attach, ok := document.Paths["/v1/gateways/{gateway_id}/consumers/{id}/policies/{policy_id}"]
	require.True(t, ok)
	description := attach.Post.Description
	assert.NotContains(t, description, "A policy with mcp_scope can only be attached to an MCP consumer",
		"rule 2 made that sentence false: a group-only scope attaches to a non-MCP consumer")
	assert.Contains(t, description, "names a registry or a tool")
	assert.Contains(t, description, "narrowing by group alone also attaches to a non-MCP consumer")
	assert.Contains(t, description, "attaching one answers 422")
	assert.Contains(t, attach.Post.Responses["422"].Description, "The policy is MCP-wide")
}

func TestPersonalKeyOpenAPIDocumentsTheSelfOnlyEndpoints(t *testing.T) {
	document := loadOpenAPIDocument(t)

	key, ok := document.Paths["/v1/gateways/{gateway_id}/store/principal/llm-key"]
	require.True(t, ok)
	rotate, ok := document.Paths["/v1/gateways/{gateway_id}/store/principal/llm-key/rotate"]
	require.True(t, ok)
	for name, tc := range map[string]struct {
		op       openAPIOperation
		statuses []string
	}{
		"GET":         {key.Get, []string{"200", "400", "403", "404"}},
		"POST":        {key.Post, []string{"201", "400", "403", "404", "409", "422"}},
		"POST rotate": {rotate.Post, []string{"200", "400", "403", "404", "422"}},
		"DELETE":      {key.Delete, []string{"204", "400", "403", "404"}},
	} {
		for _, status := range tc.statuses {
			_, ok := tc.op.Responses[status]
			assert.True(t, ok, "%s must document %s", name, status)
		}
	}

	fields := []string{"id", "consumer_ids", "key_prefix", "key_suffix", "expires_at", "enabled", "created_at", "updated_at"}
	for name, ref := range map[string]string{
		"create": key.Post.Responses["201"].Content["application/json"].Schema.Ref,
		"rotate": rotate.Post.Responses["200"].Content["application/json"].Schema.Ref,
	} {
		issued := schemaByRef(t, document, ref)
		for _, field := range append(fields, "api_key") {
			assert.Contains(t, issued.Properties, field, "%s answers %s", name, field)
		}
		assert.NotContains(t, issued.Properties, "key_hash")
	}
	read := schemaByRef(t, document, key.Get.Responses["200"].Content["application/json"].Schema.Ref)
	for _, field := range fields {
		assert.Contains(t, read.Properties, field)
	}
	assert.NotContains(t, read.Properties, "api_key", "GET never carries the secret")
	create := schemaByRef(t, document, key.Post.RequestBody.Content["application/json"].Schema.Ref)
	assert.Contains(t, create.Properties, "expires_at")
	assert.NotContains(t, create.Properties, "principal_sub", "the owner is always the caller")
	assert.Contains(t, schemaByRef(t, document, rotate.Post.RequestBody.Content["application/json"].Schema.Ref).Properties, "expires_at")
}

// refOf extracts the $ref of a property, whether inline or wrapped in allOf
// (swagger2openapi wraps referenced properties that carry a description).
func refOf(t *testing.T, property json.RawMessage) string {
	t.Helper()
	var wrapped struct {
		Ref   string `json:"$ref"`
		AllOf []struct {
			Ref string `json:"$ref"`
		} `json:"allOf"`
	}
	require.NoError(t, json.Unmarshal(property, &wrapped))
	if wrapped.Ref != "" {
		return wrapped.Ref
	}
	require.NotEmpty(t, wrapped.AllOf, "property carries no schema reference")
	return wrapped.AllOf[0].Ref
}
