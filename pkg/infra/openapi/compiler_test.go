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
