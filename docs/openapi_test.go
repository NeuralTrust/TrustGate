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
		Get  openAPIOperation `json:"get"`
		Post openAPIOperation `json:"post"`
		Put  openAPIOperation `json:"put"`
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
