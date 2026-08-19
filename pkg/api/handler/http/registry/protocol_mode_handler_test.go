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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	regmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestRegistryHandlers_InvalidProtocolModeReturnsBadRequest(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	creator := regmocks.NewCreator(t)
	updater := regmocks.NewUpdater(t)
	app := fiber.New()
	app.Post("/v1/gateways/:gateway_id/registries", registryhttp.NewCreateRegistryHandler(creator).Handle)
	app.Put("/v1/gateways/:gateway_id/registries/:id", registryhttp.NewUpdateRegistryHandler(updater).Handle)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "create",
			method: http.MethodPost,
			path:   "/v1/gateways/" + gatewayID.String() + "/registries",
			body:   `{"name":"mcp","type":"MCP","mcp_target":{"url":"https://mcp.example.com/mcp","protocol_mode":"future"}}`,
		},
		{
			name:   "update",
			method: http.MethodPut,
			path:   "/v1/gateways/" + gatewayID.String() + "/registries/" + registryID.String(),
			body:   `{"mcp_target":{"protocol_mode":"future"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer func() { require.NoError(t, resp.Body.Close()) }()
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)

			var got httpio.ErrorBody
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			require.Equal(t, "invalid_mcp_target", got.Error)
			require.Contains(t, got.Message, `unsupported protocol_mode "future"`)
		})
	}
	creator.AssertNotCalled(t, "Create")
	updater.AssertNotCalled(t, "Update")
}
