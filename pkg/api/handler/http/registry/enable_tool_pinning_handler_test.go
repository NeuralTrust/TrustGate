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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func pinnedMCPRegistry(t *testing.T) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "mcp", "", &domain.MCPTarget{URL: "https://mcp.example.com/mcp"})
	require.NoError(t, err)
	reg.ToolPolicy = domain.ToolPolicyPinned
	return reg
}

func enablePinningApp(svc appregistry.PinnedToolService, intro appmcp.Introspector) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.UserEmailContextKey), "ana@acme.io")
		return c.Next()
	})
	app.Put("/v1/gateways/:gateway_id/registries/:id/tool-pinning", registryhttp.NewEnableToolPinningHandler(svc, intro).Handle)
	return app
}

func putPinning(t *testing.T, app *fiber.App, gw ids.GatewayID, reg ids.RegistryID, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut,
		"/v1/gateways/"+gw.String()+"/registries/"+reg.String()+"/tool-pinning", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// upstreamTool builds a Tool from raw upstream bytes, as the client does.
func upstreamTool(t *testing.T, raw string) appmcp.Tool {
	t.Helper()
	var tool appmcp.Tool
	require.NoError(t, json.Unmarshal([]byte(raw), &tool))
	return tool
}

func refBody(t *testing.T, tools ...appmcp.Tool) string {
	t.Helper()
	var parts []string
	for _, tool := range tools {
		cand, err := appmcp.ToolCandidate(tool)
		require.NoError(t, err)
		parts = append(parts, fmt.Sprintf(`{"name":%q,"fingerprint":%q}`, cand.Name, cand.Fingerprint))
	}
	return `{"tools":[` + strings.Join(parts, ",") + `]}`
}

const numericTool = `{"name":"calc","description":"d","inputSchema":{"type":"object","properties":{"a":{"default":1.0},"b":{"maximum":1e3},"c":{"const":9007199254740993}}}}`

func TestEnableToolPinningHandler_ApprovesTheLiveDefinitionsNotTheClients(t *testing.T) {
	reg := pinnedMCPRegistry(t)
	live := upstreamTool(t, numericTool)
	want, err := appmcp.ToolCandidate(live)
	require.NoError(t, err)

	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Pin(mock.Anything, appregistry.PinToolsInput{
		GatewayID: reg.GatewayID, RegistryID: reg.ID, Tools: []domain.ToolCandidate{want}, DecidedBy: "ana@acme.io",
	}).Return(reg, nil)

	resp := putPinning(t, enablePinningApp(svc, &stubIntrospector{tools: []appmcp.Tool{live}}), reg.GatewayID, reg.ID, refBody(t, live))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(raw), `"tool_policy":"pinned"`)
}

func TestEnableToolPinningHandler_StaleRefIs422AndAppliesNothing(t *testing.T) {
	reg := pinnedMCPRegistry(t)
	reviewed := upstreamTool(t, `{"name":"search","description":"old"}`)
	nowLive := upstreamTool(t, `{"name":"search","description":"changed upstream"}`)
	svc := appmocks.NewPinnedToolService(t) // Pin must not run

	resp := putPinning(t, enablePinningApp(svc, &stubIntrospector{tools: []appmcp.Tool{nowLive}}), reg.GatewayID, reg.ID, refBody(t, reviewed))
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(raw), "search")
}

func TestEnableToolPinningHandler_EmptyListNeedsNoUpstream(t *testing.T) {
	reg := pinnedMCPRegistry(t)
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Pin(mock.Anything, mock.MatchedBy(func(in appregistry.PinToolsInput) bool { return len(in.Tools) == 0 })).Return(reg, nil)
	// An introspector that would fail proves it is not consulted.
	intro := &stubIntrospector{err: appmcp.ErrUpstreamUnavailable}
	resp := putPinning(t, enablePinningApp(svc, intro), reg.GatewayID, reg.ID, `{"tools":[]}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Zero(t, intro.calls)
}

func TestEnableToolPinningHandler_NotIntrospectableAcceptsOnlyAnEmptyList(t *testing.T) {
	reg := pinnedMCPRegistry(t)
	svc := appmocks.NewPinnedToolService(t) // Pin must not run
	intro := &stubIntrospector{err: fmt.Errorf("%w: per-principal", appmcp.ErrRegistryNotIntrospectable)}
	resp := putPinning(t, enablePinningApp(svc, intro), reg.GatewayID, reg.ID, `{"tools":[{"name":"a","fingerprint":"f"}]}`)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(raw), "empty list")
}

func TestEnableToolPinningHandler_UnreachableUpstreamIs502AndAppliesNothing(t *testing.T) {
	reg := pinnedMCPRegistry(t)
	svc := appmocks.NewPinnedToolService(t)
	intro := &stubIntrospector{err: fmt.Errorf("%w: dial", appmcp.ErrUpstreamUnavailable)}
	resp := putPinning(t, enablePinningApp(svc, intro), reg.GatewayID, reg.ID, `{"tools":[{"name":"a","fingerprint":"f"}]}`)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestEnableToolPinningHandler_BadBodies(t *testing.T) {
	cases := map[string]string{
		"tools missing":        `{}`,
		"not json":             `nope`,
		"missing fingerprint":  `{"tools":[{"name":"a"}]}`,
		"old definition shape": `{"tools":[{"name":"a","description":"d","inputSchema":{}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			svc := appmocks.NewPinnedToolService(t) // must not be called
			resp := putPinning(t, enablePinningApp(svc, &stubIntrospector{}), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestEnableToolPinningHandler_LLMRegistryIs422(t *testing.T) {
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Pin(mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidToolPolicy)
	resp := putPinning(t, enablePinningApp(svc, &stubIntrospector{}), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), `{"tools":[]}`)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}
