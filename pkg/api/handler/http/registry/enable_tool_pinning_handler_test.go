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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
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

func enablePinningApp(svc appregistry.PinnedToolService) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.UserEmailContextKey), "ana@acme.io")
		return c.Next()
	})
	app.Put("/v1/gateways/:gateway_id/registries/:id/tool-pinning", registryhttp.NewEnableToolPinningHandler(svc).Handle)
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

func TestEnableToolPinningHandler_ComputesFingerprintsServerSide(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := pinnedMCPRegistry(t)
	reg.GatewayID = gw
	want, err := domain.NewToolCandidate("search", "Search the web", json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`))
	require.NoError(t, err)

	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Pin(mock.Anything, appregistry.PinToolsInput{
		GatewayID: gw, RegistryID: reg.ID, Tools: []domain.ToolCandidate{want}, DecidedBy: "ana@acme.io",
	}).Return(reg, nil)

	// A fingerprint sent by the client is not a field of the body: it is dropped.
	resp := putPinning(t, enablePinningApp(svc), gw, reg.ID,
		`{"tools":[{"name":"search","description":"Search the web","inputSchema":{"properties":{"q":{"type":"string"}},"type":"object"},"fingerprint":"forged"}]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(raw), `"tool_policy":"pinned"`)
}

func TestEnableToolPinningHandler_EmptyListIsAllowed(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := pinnedMCPRegistry(t)
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Pin(mock.Anything, mock.MatchedBy(func(in appregistry.PinToolsInput) bool { return len(in.Tools) == 0 })).Return(reg, nil)
	resp := putPinning(t, enablePinningApp(svc), gw, reg.ID, `{"tools":[]}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestEnableToolPinningHandler_BadBodies(t *testing.T) {
	big := strings.Repeat("x", 70<<10)
	cases := map[string]struct {
		body string
		want int
	}{
		"tools missing":   {`{}`, http.StatusBadRequest},
		"not json":        {`nope`, http.StatusBadRequest},
		"nameless tool":   {`{"tools":[{"description":"d"}]}`, http.StatusBadRequest},
		"oversized tool":  {`{"tools":[{"name":"a","description":"` + big + `"}]}`, http.StatusBadRequest},
		"NUL in a string": {`{"tools":[{"name":"a","description":"x\u0000y"}]}`, http.StatusUnprocessableEntity},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc := appmocks.NewPinnedToolService(t) // must not be called
			resp := putPinning(t, enablePinningApp(svc), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), tc.body)
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

func TestEnableToolPinningHandler_LLMRegistryIs422(t *testing.T) {
	svc := appmocks.NewPinnedToolService(t)
	svc.EXPECT().Pin(mock.Anything, mock.Anything).Return(nil, domain.ErrInvalidToolPolicy)
	resp := putPinning(t, enablePinningApp(svc), ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), `{"tools":[]}`)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}
