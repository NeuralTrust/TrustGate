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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
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
			"servers": [{"url": "` + baseURL + `/v1"}],
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

func TestUnsafeIPRejectsPrivateAndReservedNetworks(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"192.0.2.1",
		"2001:db8::1",
	} {
		if !unsafeIP(net.ParseIP(value)) {
			t.Fatalf("unsafeIP(%q) = false", value)
		}
	}
	if unsafeIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("unsafeIP(public address) = true")
	}
}
