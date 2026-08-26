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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	infraopenapi "github.com/NeuralTrust/TrustGate/pkg/infra/openapi"
	"github.com/stretchr/testify/require"
)

type compilerFunc func(context.Context, appopenapi.Source) (*appopenapi.Document, error)

func (f compilerFunc) Compile(ctx context.Context, source appopenapi.Source) (*appopenapi.Document, error) {
	return f(ctx, source)
}

func TestOpenAPIUpstreamListsAndCallsTools(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/pets/42", r.URL.Path)
		require.Equal(t, "full", r.URL.Query().Get("view"))
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.JSONEq(t, `{"name":"Milo"}`, string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"name":"Milo"}`))
	}))
	defer server.Close()

	var compiles atomic.Int32
	compiler := compilerFunc(func(context.Context, appopenapi.Source) (*appopenapi.Document, error) {
		compiles.Add(1)
		return &appopenapi.Document{
			BaseURL: server.URL + "/v1",
			Operations: []appopenapi.Operation{{
				Name:        "updatePet",
				Description: "Update a pet",
				Method:      http.MethodPost,
				Path:        "/pets/{id}",
				InputSchema: json.RawMessage(`{
					"type":"object",
					"properties":{"id":{"type":"integer"},"view":{"type":"string"},"name":{"type":"string"}},
					"required":["id","name"]
				}`),
				OutputSchema: json.RawMessage(`{
					"type":"object",
					"properties":{"id":{"type":"integer"},"name":{"type":"string"}}
				}`),
				Parameters: []appopenapi.Parameter{
					{Name: "id", In: "path", Required: true},
					{Name: "view", In: "query"},
				},
				BodyFields: []string{"name"},
			}},
		}, nil
	})
	dialer := NewDialerWithClient(nil, compiler, server.Client())
	target := appmcp.Target{
		Headers:  map[string]string{"Authorization": "Bearer token"},
		Revision: "registry:1",
		OpenAPI:  &appopenapi.Source{SpecURL: "https://spec.example/openapi.json"},
	}

	upstream, err := dialer.Connect(context.Background(), target)
	require.NoError(t, err)
	tools, err := upstream.ListTools(context.Background())
	require.NoError(t, err)
	require.Len(t, tools, 1)
	toolJSON, err := json.Marshal(tools[0])
	require.NoError(t, err)
	require.JSONEq(t, `{
		"name":"updatePet",
		"description":"Update a pet",
		"inputSchema":{
			"type":"object",
			"properties":{"id":{"type":"integer"},"view":{"type":"string"},"name":{"type":"string"}},
			"required":["id","name"]
		},
		"outputSchema":{
			"type":"object",
			"properties":{"id":{"type":"integer"},"name":{"type":"string"}}
		}
	}`, string(toolJSON))
	require.False(t, upstream.SupportsResources())
	require.False(t, upstream.SupportsPrompts())
	resources, err := upstream.ListResources(context.Background())
	require.NoError(t, err)
	require.Empty(t, resources)
	prompts, err := upstream.ListPrompts(context.Background())
	require.NoError(t, err)
	require.Empty(t, prompts)

	result, err := upstream.CallTool(
		context.Background(),
		"updatePet",
		json.RawMessage(`{"id":42,"view":"full","name":"Milo"}`),
	)
	require.NoError(t, err)
	require.Contains(t, string(result), `"structuredContent":{"id":42,"name":"Milo"}`)
	require.Equal(t, int32(1), calls.Load())

	_, err = dialer.Connect(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, int32(1), compiles.Load())
}

func TestOpenAPIUpstreamCallsTrustGateAdminHealthz(t *testing.T) {
	t.Parallel()
	spec := readTrustGateAdminOpenAPI(t)
	var healthCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(spec)
		case r.Method == http.MethodGet && r.URL.Path == "/healthz":
			healthCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dialer := NewDialerWithClient(nil, infraopenapi.NewCompilerWithClient(server.Client()), server.Client())
	upstream, err := dialer.Connect(context.Background(), appmcp.Target{
		Revision: "trustgate-admin:1",
		OpenAPI: &appopenapi.Source{
			SpecURL: server.URL + "/openapi.json",
			BaseURL: server.URL,
		},
	})
	require.NoError(t, err)
	require.False(t, upstream.SupportsPrompts())
	require.False(t, upstream.SupportsResources())

	tools, err := upstream.ListTools(context.Background())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(tools), 50)
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	require.Contains(t, names, "get_healthz")

	result, err := upstream.CallTool(context.Background(), "get_healthz", json.RawMessage(`{}`))
	require.NoError(t, err)
	require.Contains(t, string(result), `"status":"ok"`)
	require.Equal(t, int32(1), healthCalls.Load())
}

func readTrustGateAdminOpenAPI(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..", "docs", "openapi.json"))
	require.NoError(t, err)
	return data
}

func TestOpenAPIUpstreamRejectsInvalidArguments(t *testing.T) {
	t.Parallel()
	compiler := compilerFunc(func(context.Context, appopenapi.Source) (*appopenapi.Document, error) {
		return &appopenapi.Document{
			Version: "3.0.3",
			BaseURL: "https://api.example.com",
			Operations: []appopenapi.Operation{{
				Name:   "getPet",
				Method: http.MethodGet,
				Path:   "/pets/{id}",
				InputSchema: json.RawMessage(`{
					"type":"object",
					"properties":{"id":{"type":"integer","minimum":0,"exclusiveMinimum":true}},
					"required":["id"]
				}`),
			}},
		}, nil
	})
	dialer := NewDialerWithClient(nil, compiler, http.DefaultClient)
	upstream, err := dialer.Connect(context.Background(), appmcp.Target{
		OpenAPI: &appopenapi.Source{SpecURL: "https://spec.example/openapi.json"},
	})
	require.NoError(t, err)

	_, err = upstream.CallTool(context.Background(), "getPet", json.RawMessage(`{}`))
	var rpcErr *appmcp.RPCError
	require.ErrorAs(t, err, &rpcErr)
	require.Equal(t, int64(-32602), rpcErr.Code)
}

func TestDialerPreservesRemoteMCPPath(t *testing.T) {
	t.Parallel()
	var called bool
	remoteUpstream := &fakeRemoteUpstream{}
	remote := appmcp.DialerFunc(func(_ context.Context, target appmcp.Target) (appmcp.Upstream, error) {
		called = true
		require.Equal(t, "https://mcp.example.com/mcp", target.URL)
		return remoteUpstream, nil
	})
	dialer := NewDialerWithClient(remote, nil, http.DefaultClient)

	upstream, err := dialer.Connect(context.Background(), appmcp.Target{URL: "https://mcp.example.com/mcp"})
	require.NoError(t, err)
	require.True(t, called)
	require.Same(t, remoteUpstream, upstream)
}

func TestAddQuerySupportsOpenAPISerializationStyles(t *testing.T) {
	t.Parallel()
	query := make(url.Values)
	addQuery(query, "tags", []any{"red", "blue"}, "pipeDelimited", false)
	addQuery(query, "filter", map[string]any{"status": "active", "limit": 10}, "deepObject", true)

	require.Equal(t, "red|blue", query.Get("tags"))
	require.Equal(t, "active", query.Get("filter[status]"))
	require.Equal(t, "10", query.Get("filter[limit]"))
}

type fakeRemoteUpstream struct{}

func (*fakeRemoteUpstream) ListTools(context.Context) ([]appmcp.Tool, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) CallTool(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) ListResources(context.Context) ([]appmcp.Resource, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) ListResourceTemplates(context.Context) ([]appmcp.ResourceTemplate, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) ReadResource(context.Context, string) (json.RawMessage, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) ListPrompts(context.Context) ([]appmcp.Prompt, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) GetPrompt(context.Context, string, map[string]string) (json.RawMessage, error) {
	return nil, nil
}

func (*fakeRemoteUpstream) SupportsResources() bool {
	return false
}

func (*fakeRemoteUpstream) SupportsPrompts() bool {
	return false
}

func (*fakeRemoteUpstream) Close(context.Context) {
}
