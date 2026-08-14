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

package router_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMCPRouterDispatch(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	gateway := &gatewaydomain.Gateway{ID: gatewayID, Slug: "tenant"}
	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindBySlug(mock.Anything, "tenant").Return(gateway, nil).Times(3)

	apiKeyConnect := oauthmocks.NewAPIKeyConnectService(t)
	apiKeyConnect.EXPECT().ValidateTarget(mock.Anything, gatewayID, "tools").Return(nil).Twice()
	apiKeyConnect.EXPECT().
		CreateTicket(mock.Anything, gatewayID, "tools", "secret-key").
		Return("self-service-ticket", nil).
		Once()

	connect := oauthmocks.NewConnectService(t)
	connect.EXPECT().
		Page(mock.Anything, "existing-ticket").
		Return(&appoauth.ConnectPage{ConsumerPath: "/tools/mcp"}, nil).
		Once()
	connect.EXPECT().
		Start(mock.Anything, mock.Anything, "oauth-ticket", "provider").
		Return("https://provider.example/authorize", nil).
		Once()

	apiKeyHandler := oauthhttp.NewAPIKeyConnectHandler(
		resolver.NewSubdomainGatewayResolver(gateways, "mcp.test"),
		apiKeyConnect,
		appoauth.NewNoopConnectAttemptLimiter(),
		func(string, string) string { return "127.0.0.1" },
	)
	connectHandler := oauthhttp.NewConnectHandler(connect)
	mcpHandler := mcphttp.NewHandler(nil, nil)
	mcpRouter := router.NewMCPRouter(
		middleware.NewTransport(),
		middleware.NewTransport(middleware.NewSecurityHeadersMiddleware()),
		apihandler.NewHealthHandler(),
		mcpHandler,
		new(oauthhttp.ProtectedResourceHandler),
		new(oauthhttp.AuthorizationServerHandler),
		new(oauthhttp.RegisterHandler),
		new(oauthhttp.AuthorizeHandler),
		new(oauthhttp.CallbackHandler),
		new(oauthhttp.TokenHandler),
		apiKeyHandler,
		connectHandler,
		new(oauthhttp.JWKSHandler),
		nil,
	)
	app := fiber.New()
	require.NoError(t, mcpRouter.BuildRoutes(app))

	t.Run("GET self-service route", func(t *testing.T) {
		res, body := dispatchMCPRequest(t, app, fiber.MethodGet, "/tools/connect", "", "")

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
		assert.Contains(t, body, `action="/tools/connect"`)
	})

	t.Run("GET single-segment connect with ticket stays self-service", func(t *testing.T) {
		res, body := dispatchMCPRequest(
			t,
			app,
			fiber.MethodGet,
			"/tools/connect?ticket=shadow-ticket",
			"",
			"",
		)

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
		assert.Contains(t, body, `action="/tools/connect"`)
		assert.NotContains(t, body, "shadow-ticket")
	})

	t.Run("POST self-service route", func(t *testing.T) {
		res, _ := dispatchMCPRequest(
			t,
			app,
			fiber.MethodPost,
			"/tools/connect",
			"api_key=secret-key",
			fiber.MIMEApplicationForm,
		)

		assert.Equal(t, fiber.StatusSeeOther, res.StatusCode)
		assert.Equal(t, "/tools/mcp/connect?ticket=self-service-ticket", res.Header.Get(fiber.HeaderLocation))
		assert.Empty(t, res.Header.Get("X-Frame-Options"))
	})

	t.Run("existing nested connect route", func(t *testing.T) {
		res, body := dispatchMCPRequest(
			t,
			app,
			fiber.MethodGet,
			"/tools/mcp/connect?ticket=existing-ticket",
			"",
			"",
		)

		assert.Equal(t, fiber.StatusOK, res.StatusCode)
		assert.Contains(t, body, "/tools/mcp")
	})

	t.Run("existing OAuth connect route", func(t *testing.T) {
		res, _ := dispatchMCPRequest(
			t,
			app,
			fiber.MethodGet,
			"/oauth/connect/provider?ticket=oauth-ticket",
			"",
			"",
		)

		assert.Equal(t, fiber.StatusFound, res.StatusCode)
		assert.Equal(t, "https://provider.example/authorize", res.Header.Get(fiber.HeaderLocation))
	})

	t.Run("generic MCP methods", func(t *testing.T) {
		getResponse, _ := dispatchMCPRequest(t, app, fiber.MethodGet, "/tools/mcp", "", "")
		assert.Equal(t, fiber.StatusMethodNotAllowed, getResponse.StatusCode)
		assert.Equal(t, fiber.MethodPost, getResponse.Header.Get(fiber.HeaderAllow))

		deleteResponse, _ := dispatchMCPRequest(t, app, fiber.MethodDelete, "/tools/mcp", "", "")
		assert.Equal(t, fiber.StatusMethodNotAllowed, deleteResponse.StatusCode)
		assert.Equal(t, fiber.MethodPost, deleteResponse.Header.Get(fiber.HeaderAllow))

		postResponse, _ := dispatchMCPRequest(t, app, fiber.MethodPost, "/tools/mcp", `{}`, fiber.MIMEApplicationJSON)
		assert.Equal(t, fiber.StatusUnauthorized, postResponse.StatusCode)
		assert.Equal(t, "DENY", postResponse.Header.Get("X-Frame-Options"))
	})
}

func dispatchMCPRequest(
	t *testing.T,
	app *fiber.App,
	method string,
	target string,
	body string,
	contentType string,
) (*http.Response, string) {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "tenant.mcp.test"
	if contentType != "" {
		req.Header.Set(fiber.HeaderContentType, contentType)
	}
	res, err := app.Test(req, -1)
	require.NoError(t, err)

	responseBody, readErr := io.ReadAll(res.Body)
	closeErr := res.Body.Close()
	require.NoError(t, readErr)
	require.NoError(t, closeErr)
	return res, string(responseBody)
}
