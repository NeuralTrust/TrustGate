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

package registry_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubIntrospector stands in for appmcp.Introspector: the interface has no
// generated mock, and the handler only needs a canned answer per case.
type stubIntrospector struct {
	tools    []appmcp.Tool
	err      error
	calls    int
	gotGwID  ids.GatewayID
	gotRegID ids.RegistryID
}

func (s *stubIntrospector) ListRegistryTools(
	_ context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) ([]appmcp.Tool, error) {
	s.calls++
	s.gotGwID = gatewayID
	s.gotRegID = registryID
	return s.tools, s.err
}

func newListRegistryToolsApp(h *registryhttp.ListRegistryToolsHandler) *fiber.App {
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/registries/:id/tools", h.Handle)
	return app
}

func listRegistryTools(t *testing.T, sut *stubIntrospector) (*http.Response, map[string]any) {
	t.Helper()
	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	app := newListRegistryToolsApp(registryhttp.NewListRegistryToolsHandler(sut))
	url := "/v1/gateways/" + gwID.String() + "/registries/" + regID.String() + "/tools"

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, url, nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))

	assert.Equal(t, 1, sut.calls)
	assert.Equal(t, gwID, sut.gotGwID)
	assert.Equal(t, regID, sut.gotRegID)
	return resp, body
}

func TestListRegistryToolsHandler_OK_ReturnsNativeUnprefixedNames(t *testing.T) {
	sut := &stubIntrospector{tools: []appmcp.Tool{
		{Name: "search_threads"},
		{Name: "create_issue"},
	}}

	resp, body := listRegistryTools(t, sut)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	tools, ok := body["tools"].([]any)
	require.True(t, ok)
	require.Len(t, tools, 2)

	names := make([]string, 0, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		require.True(t, ok)
		name, ok := tool["name"].(string)
		require.True(t, ok)
		names = append(names, name)
	}
	// The handler does not run resolveNames, so the wire carries the upstream's
	// own tool names. That is the value mcp_scope.tools[].tool stores.
	assert.Equal(t, []string{"search_threads", "create_issue"}, names)
	for _, name := range names {
		assert.NotContains(t, name, "__", "names must stay native, not registry-prefixed")
	}
}

func TestListRegistryToolsHandler_OK_EmptyToolsIsArrayNotNull(t *testing.T) {
	sut := &stubIntrospector{tools: nil}

	resp, body := listRegistryTools(t, sut)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	tools, ok := body["tools"].([]any)
	require.True(t, ok, "tools must serialize as [], never null")
	assert.Empty(t, tools)
}

func TestListRegistryToolsHandler_NotIntrospectable_PerPrincipalAuth(t *testing.T) {
	sut := &stubIntrospector{err: fmt.Errorf(
		"%w: registry uses passthrough auth",
		appmcp.ErrRegistryNotIntrospectable,
	)}

	resp, body := listRegistryTools(t, sut)

	require.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "conflict", body["error"])
}

func TestListRegistryToolsHandler_NotIntrospectable_URLVariables(t *testing.T) {
	sut := &stubIntrospector{err: fmt.Errorf(
		"%w: registry declares url variables",
		appmcp.ErrRegistryNotIntrospectable,
	)}

	resp, body := listRegistryTools(t, sut)

	require.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.NotEqual(t, http.StatusUnprocessableEntity, resp.StatusCode,
		"the request is well formed; it is the registry that cannot be introspected")
	assert.Equal(t, "conflict", body["error"])
}

func TestListRegistryToolsHandler_UpstreamUnavailable(t *testing.T) {
	sut := &stubIntrospector{err: fmt.Errorf(
		"%w: tools/list failed",
		appmcp.ErrUpstreamUnavailable,
	)}

	resp, body := listRegistryTools(t, sut)

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.Contains(t, body["error"], "upstream unavailable")
}

func TestListRegistryToolsHandler_RegistryNotFound(t *testing.T) {
	sut := &stubIntrospector{err: fmt.Errorf("registry: %w", commonerrors.ErrNotFound)}

	resp, body := listRegistryTools(t, sut)

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "not_found", body["error"])
}

func TestListRegistryToolsHandler_InvalidRegistryID(t *testing.T) {
	sut := &stubIntrospector{}
	gwID := ids.New[ids.GatewayKind]()
	app := newListRegistryToolsApp(registryhttp.NewListRegistryToolsHandler(sut))

	resp, err := app.Test(httptest.NewRequest(
		http.MethodGet,
		"/v1/gateways/"+gwID.String()+"/registries/not-a-uuid/tools",
		nil,
	))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Zero(t, sut.calls)
}
