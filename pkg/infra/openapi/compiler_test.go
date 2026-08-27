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

package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/require"
)

func TestCompilerCompilesOperationsIntoTools(t *testing.T) {
	t.Parallel()
	var baseURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"openapi": "3.0.3",
			"info": {"title": "Pet API", "version": "1.0"},
			"servers": [{
				"url": "` + baseURL + `/{version}",
				"variables": {"version": {"default": "v1"}}
			}],
			"paths": {
				"/pets/{petId}": {
					"get": {
						"operationId": "getPet",
						"summary": "Get a pet",
						"parameters": [
							{"name": "petId", "in": "path", "required": true, "schema": {"type": "integer"}},
							{"name": "include", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}}
						],
						"responses": {"200": {
							"description": "ok",
							"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}
						}}
					}
				},
				"/pets": {
					"post": {
						"operationId": "createPet",
						"requestBody": {
							"required": true,
							"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}
						},
						"responses": {"201": {"description": "created"}}
					}
				}
			},
			"components": {"schemas": {"Pet": {
				"type": "object",
				"required": ["name"],
				"properties": {"name": {"type": "string"}, "age": {"type": "integer"}}
			}}}
		}`))
	}))
	defer server.Close()
	baseURL = server.URL

	compiler := NewCompilerWithClient(server.Client())
	document, err := compiler.Compile(context.Background(), appopenapi.Source{SpecURL: server.URL})
	require.NoError(t, err)
	require.Equal(t, "3.0.3", document.Version)
	require.Equal(t, "Pet API", document.Title)
	require.Equal(t, server.URL+"/v1", document.BaseURL)
	require.Len(t, document.Operations, 2)

	operations := make(map[string]appopenapi.Operation)
	for _, operation := range document.Operations {
		operations[operation.Name] = operation
	}
	getPet := operations["getPet"]
	require.Equal(t, "GET", getPet.Method)
	require.Equal(t, "/pets/{petId}", getPet.Path)
	require.Equal(t, "path", getPet.Parameters[0].In)
	require.NotEmpty(t, getPet.OutputSchema)

	var schema map[string]any
	require.NoError(t, json.Unmarshal(operations["createPet"].InputSchema, &schema))
	properties := schema["properties"].(map[string]any)
	require.Contains(t, properties, "name")
	require.Contains(t, properties, "age")
	require.ElementsMatch(t, []any{"name"}, schema["required"])
}

func TestCompilerCompilesTrustGateAdminOpenAPI(t *testing.T) {
	t.Parallel()
	spec := readTrustGateAdminOpenAPI(t)
	var requested string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(spec)
	}))
	defer server.Close()

	document, err := NewCompilerWithClient(server.Client()).Compile(context.Background(), appopenapi.Source{
		SpecURL: server.URL + "/openapi.json",
		BaseURL: server.URL,
	})
	require.NoError(t, err)
	require.Equal(t, "/openapi.json", requested)
	require.Equal(t, "3.0.0", document.Version)
	require.Equal(t, "TrustGate Admin API", document.Title)
	require.Equal(t, server.URL, document.BaseURL)
	require.GreaterOrEqual(t, len(document.Operations), 50)
	require.LessOrEqual(t, len(document.Operations), maxCompiledOperations)

	byRoute := make(map[string]appopenapi.Operation, len(document.Operations))
	for _, operation := range document.Operations {
		byRoute[operation.Method+" "+operation.Path] = operation
	}
	require.Contains(t, byRoute, "GET /healthz")
	require.Contains(t, byRoute, "POST /v1/gateways")
	require.Contains(t, byRoute, "POST /v1/gateways/{gateway_id}/registries/validate-openapi")
	require.NotEmpty(t, byRoute["GET /healthz"].Name)
	require.NotEmpty(t, byRoute["GET /healthz"].OutputSchema)

	// The admin document describes most of its payloads through components, so
	// it is the case that first surfaced tools shipping a "$ref" no client can
	// resolve. Every schema has to stand on its own.
	for _, operation := range document.Operations {
		requireSelfContainedSchema(t, operation.Name+" input", operation.InputSchema)
		requireSelfContainedSchema(t, operation.Name+" output", operation.OutputSchema)
	}
}

// requireSelfContainedSchema fails when a compiled schema still points at the
// document it came from. A tool schema travels alone: the client sees it
// without "components", so any "$ref" left in it dangles.
func requireSelfContainedSchema(t *testing.T, label string, schema json.RawMessage) {
	t.Helper()
	if len(schema) == 0 {
		return
	}
	var decoded any
	require.NoError(t, json.Unmarshal(schema, &decoded), label)
	require.Empty(t, collectRefs(decoded), "%s carries unresolvable references", label)
}

func collectRefs(node any) []string {
	var found []string
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			if key == "$ref" {
				if ref, ok := value.(string); ok {
					found = append(found, ref)
				}
				continue
			}
			found = append(found, collectRefs(value)...)
		}
	case []any:
		for _, value := range typed {
			found = append(found, collectRefs(value)...)
		}
	}
	return found
}

func TestCompilerInlinesComponentReferences(t *testing.T) {
	t.Parallel()
	document := compileSpec(t, `{
		"openapi": "3.0.3",
		"info": {"title": "Pet API", "version": "1.0"},
		"paths": {
			"/pets": {
				"post": {
					"operationId": "createPet",
					"parameters": [
						{"name": "tag", "in": "query", "schema": {"$ref": "#/components/schemas/Tag"}}
					],
					"requestBody": {
						"required": true,
						"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}
					},
					"responses": {"201": {
						"description": "created",
						"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}
					}}
				}
			}
		},
		"components": {"schemas": {
			"Tag": {"type": "string", "enum": ["cat", "dog"]},
			"Breed": {"type": "object", "properties": {"label": {"type": "string"}}},
			"Pet": {
				"type": "object",
				"required": ["name"],
				"properties": {
					"name": {"type": "string"},
					"breed": {"$ref": "#/components/schemas/Breed"},
					"litter": {"type": "array", "items": {"$ref": "#/components/schemas/Breed"}}
				}
			}
		}}
	}`)
	require.Len(t, document.Operations, 1)
	operation := document.Operations[0]
	requireSelfContainedSchema(t, "input", operation.InputSchema)
	requireSelfContainedSchema(t, "output", operation.OutputSchema)

	var input map[string]any
	require.NoError(t, json.Unmarshal(operation.InputSchema, &input))
	properties, ok := input["properties"].(map[string]any)
	require.True(t, ok)

	tag, ok := properties["tag"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{"cat", "dog"}, tag["enum"])

	// The referenced schemas have to arrive with their own contents, nested
	// references included, not as a pointer the client cannot follow.
	breed, ok := properties["breed"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, breed["properties"], "label")

	litter, ok := properties["litter"].(map[string]any)
	require.True(t, ok)
	items, ok := litter["items"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, items["properties"], "label")
}

func TestCompilerCutsSelfReferencingSchemas(t *testing.T) {
	t.Parallel()
	document := compileSpec(t, `{
		"openapi": "3.0.3",
		"info": {"title": "Tree API", "version": "1.0"},
		"paths": {
			"/nodes": {
				"post": {
					"operationId": "createNode",
					"requestBody": {
						"required": true,
						"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Node"}}}
					},
					"responses": {"201": {"description": "created"}}
				}
			}
		},
		"components": {"schemas": {"Node": {
			"type": "object",
			"properties": {
				"label": {"type": "string"},
				"children": {"type": "array", "items": {"$ref": "#/components/schemas/Node"}}
			}
		}}}
	}`)
	require.Len(t, document.Operations, 1)
	// A schema that contains itself cannot be expanded forever. Compilation has
	// to end, and what it produces still cannot carry a reference.
	requireSelfContainedSchema(t, "input", document.Operations[0].InputSchema)

	var input map[string]any
	require.NoError(t, json.Unmarshal(document.Operations[0].InputSchema, &input))
	properties := input["properties"].(map[string]any)
	require.Contains(t, properties, "label")
	children, ok := properties["children"].(map[string]any)
	require.True(t, ok)
	// The recursive branch is cut with a schema that accepts anything, so the
	// surrounding fields keep their meaning.
	require.Equal(t, map[string]any{}, children["items"])
}

func TestCompilerOmitsOutputSchemaForNonObjectResponses(t *testing.T) {
	t.Parallel()
	document := compileSpec(t, `{
		"openapi": "3.0.3",
		"info": {"title": "Pet API", "version": "1.0"},
		"paths": {
			"/pets": {
				"get": {
					"operationId": "listPets",
					"responses": {"200": {
						"description": "ok",
						"content": {"application/json": {"schema": {
							"type": "array",
							"items": {"type": "object", "properties": {"name": {"type": "string"}}}
						}}}
					}}
				}
			},
			"/pets/{petId}": {
				"get": {
					"operationId": "getPet",
					"parameters": [{"name": "petId", "in": "path", "required": true, "schema": {"type": "string"}}],
					"responses": {"200": {
						"description": "ok",
						"content": {"application/json": {"schema": {
							"type": "object",
							"properties": {"name": {"type": "string"}}
						}}}
					}}
				}
			}
		}
	}`)
	operations := make(map[string]appopenapi.Operation, len(document.Operations))
	for _, operation := range document.Operations {
		operations[operation.Name] = operation
	}
	// A tool that announces an output schema owes the client a structured
	// result, and MCP only carries those as objects. A list endpoint would
	// promise something it cannot deliver, so it says nothing instead.
	require.Empty(t, operations["listPets"].OutputSchema)
	require.NotEmpty(t, operations["getPet"].OutputSchema)
}

func compileSpec(t *testing.T, spec string) *appopenapi.Document {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(spec))
	}))
	t.Cleanup(server.Close)
	document, err := NewCompilerWithClient(server.Client()).Compile(context.Background(), appopenapi.Source{
		SpecURL: server.URL,
		BaseURL: server.URL,
	})
	require.NoError(t, err)
	return document
}

func readTrustGateAdminOpenAPI(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "docs", "openapi.json"))
	require.NoError(t, err)
	require.Greater(t, len(data), 1024)
	require.LessOrEqual(t, len(data), maxSpecBytes)
	return data
}

func TestCompilerReportsFetchAndParseStages(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer server.Close()
	compiler := NewCompilerWithClient(server.Client())

	_, err := compiler.Compile(context.Background(), appopenapi.Source{SpecURL: server.URL})
	var compileErr *appopenapi.CompileError
	require.ErrorAs(t, err, &compileErr)
	require.Equal(t, appopenapi.StageFetch, compileErr.Stage)
}

func TestCompilerSetsOpenAPIUserAgent(t *testing.T) {
	t.Parallel()
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"openapi": "3.0.0",
			"info": {"title": "UA", "version": "1"},
			"paths": {"/ok": {"get": {"responses": {"200": {"description": "ok"}}}}}
		}`))
	}))
	defer server.Close()

	_, err := NewCompilerWithClient(server.Client()).Compile(context.Background(), appopenapi.Source{
		SpecURL: server.URL,
		BaseURL: server.URL,
	})
	require.NoError(t, err)
	require.Equal(t, "TrustGate-OpenAPI/1.0", userAgent)
}

func TestBlockedDestinationAllowsPrivateAddressesForFQDNs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host    string
		ip      string
		blocked bool
	}{
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "10.0.0.1", blocked: false},
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "100.64.0.1", blocked: false},
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "192.168.1.8", blocked: false},
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "8.8.8.8", blocked: false},
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "127.0.0.1", blocked: true},
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "169.254.169.254", blocked: true},
		{host: "agentgateway-admin.dev.neuraltrust.ai", ip: "192.0.2.1", blocked: true},
		{host: "10.0.0.1", ip: "10.0.0.1", blocked: true},
		{host: "100.64.0.1", ip: "100.64.0.1", blocked: true},
		{host: "8.8.8.8", ip: "8.8.8.8", blocked: false},
	}
	for _, tc := range cases {
		if got := blockedDestination(tc.host, net.ParseIP(tc.ip)); got != tc.blocked {
			t.Fatalf("blockedDestination(%q, %s) = %v, want %v", tc.host, tc.ip, got, tc.blocked)
		}
	}
}

func TestValidatePublicURLRejectsLiteralReservedDestination(t *testing.T) {
	t.Parallel()
	err := validatePublicURL(context.Background(), "http://169.254.169.254/api")
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked address")
}

func TestCompileOperationsFoldsMissingOperationIDsIntoOneWarning(t *testing.T) {
	t.Parallel()
	paths := openapi3.NewPathsWithCapacity(3)
	for _, path := range []string{"/v1/providers-catalog", "/v1/models-catalog", "/healthz"} {
		paths.Set(path, &openapi3.PathItem{Get: &openapi3.Operation{}})
	}

	operations, warnings, err := compileOperations(&openapi3.T{Paths: paths})
	require.NoError(t, err)
	require.Len(t, operations, 3)
	require.Len(t, warnings, 1)
	require.Equal(t, "synthetic_tool_name", warnings[0].Code)
	require.Contains(t, warnings[0].Message, "3 operations without operationId")

	names := make([]string, 0, len(operations))
	for _, operation := range operations {
		names = append(names, operation.Name)
	}
	require.Contains(t, names, "get_v1_providers_catalog")
	require.Contains(t, names, "get_healthz")
}

func TestCompileOperationsCapsSkippedOperationList(t *testing.T) {
	t.Parallel()
	total := maxListedSkips + 3
	paths := openapi3.NewPathsWithCapacity(total)
	for index := 0; index < total; index++ {
		paths.Set(fmt.Sprintf("/upload/%d", index), &openapi3.PathItem{
			Post: &openapi3.Operation{
				OperationID: fmt.Sprintf("upload%d", index),
				RequestBody: &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithContent(
					openapi3.NewContentWithFormDataSchema(openapi3.NewObjectSchema()),
				)},
			},
		})
	}

	operations, warnings, err := compileOperations(&openapi3.T{Paths: paths})
	require.NoError(t, err)
	require.Empty(t, operations)
	require.Len(t, warnings, 1)
	require.Equal(t, "unsupported_operation", warnings[0].Code)
	require.Contains(t, warnings[0].Message, fmt.Sprintf("%d operations skipped", total))
	require.Contains(t, warnings[0].Message, "and 3 more")
}

func TestCompilerSummarizesTrustGateAdminWarnings(t *testing.T) {
	t.Parallel()
	spec := readTrustGateAdminOpenAPI(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(spec)
	}))
	defer server.Close()

	document, err := NewCompilerWithClient(server.Client()).Compile(context.Background(), appopenapi.Source{
		SpecURL: server.URL + "/openapi.json",
		BaseURL: server.URL,
	})
	require.NoError(t, err)
	counts := make(map[string]int)
	for _, warning := range document.Warnings {
		counts[warning.Code]++
	}
	require.LessOrEqual(t, counts["synthetic_tool_name"], 1)
	require.LessOrEqual(t, counts["unsupported_operation"], 1)
	require.Less(t, len(document.Warnings), 5)
}

func TestCompileOperationsRejectsExcessiveToolsets(t *testing.T) {
	t.Parallel()
	paths := openapi3.NewPathsWithCapacity(maxCompiledOperations + 1)
	for index := 0; index <= maxCompiledOperations; index++ {
		paths.Set(fmt.Sprintf("/items/%d", index), &openapi3.PathItem{
			Get: &openapi3.Operation{OperationID: fmt.Sprintf("getItem%d", index)},
		})
	}
	_, _, err := compileOperations(&openapi3.T{Paths: paths})
	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum supported")
}
