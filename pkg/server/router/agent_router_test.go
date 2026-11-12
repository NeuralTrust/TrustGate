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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	a2ahttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/a2a"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestAgentRouter_HealthRoutes(t *testing.T) {
	recorder := &routerOpsRecorder{}
	r := router.NewAgentRouter(
		middleware.NewTransport(),
		middleware.NewTransport(),
		apihandler.NewHealthHandler(),
		middleware.NewOpsMetricsMiddleware(recorder, o11y.PlaneAgent),
		a2ahttp.NewHandler(nil),
		jwksHandler(t),
	)
	app := fiber.New()
	require.NoError(t, r.BuildRoutes(app))

	for _, path := range []string{router.HealthPath, router.HealthPathAlias, router.ReadyPath} {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.Equal(t, o11y.PlaneAgent, recorder.request.Plane)
		require.Equal(t, o11y.RouteHealth, recorder.request.Route)
	}

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/app/mcp", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func jwksHandler(t *testing.T) *oauthhttp.JWKSHandler {
	t.Helper()
	signer, err := infrasts.NewSigner("https://sts.example", "", nil)
	require.NoError(t, err)
	return oauthhttp.NewJWKSHandler(signer)
}

func TestAgentRouter_JWKSNeedsNoCredential(t *testing.T) {
	r := router.NewAgentRouter(
		middleware.NewTransport(),
		middleware.NewTransport(denyAll{}),
		apihandler.NewHealthHandler(),
		nil,
		a2ahttp.NewHandler(nil),
		jwksHandler(t),
	)
	app := fiber.New()
	require.NoError(t, r.BuildRoutes(app))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, oauthhttp.JWKSPath, nil))
	require.NoError(t, err)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, jwks.Keys, 1)
}

type denyAll struct{}

func (denyAll) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if c.Get("X-Allow") == "" {
			return fiber.ErrUnauthorized
		}
		return c.Next()
	}
}

func TestAgentRouter_AgentRoutesRunTheAuthTransport(t *testing.T) {
	r := router.NewAgentRouter(
		middleware.NewTransport(),
		middleware.NewTransport(denyAll{}),
		apihandler.NewHealthHandler(),
		nil,
		a2ahttp.NewHandler(nil),
		jwksHandler(t),
	)
	app := fiber.New()
	require.NoError(t, r.BuildRoutes(app))

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/app/agents/research", nil),
		httptest.NewRequest(http.MethodGet, "/app/agents/research/.well-known/agent-card.json", nil),
	} {
		resp, err := app.Test(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		req.Header.Set("X-Allow", "1")
		resp, err = app.Test(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "no A2A consumer on the context")
	}
}
