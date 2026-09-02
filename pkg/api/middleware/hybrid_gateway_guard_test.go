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

package middleware_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newHybridGuardApp mounts the guard behind a stub that injects gw into the
// user context, standing in for the auth middleware that resolves the gateway.
func newHybridGuardApp(t *testing.T, serveHybrid bool, gw *gatewaydomain.Gateway) *fiber.App {
	t.Helper()
	cfg := &config.Config{Server: config.ServerConfig{ServeHybridGateways: serveHybrid}}
	guard := middleware.NewHybridGatewayGuardMiddleware(cfg)

	app := fiber.New()
	app.Get("/route",
		func(c *fiber.Ctx) error {
			if gw != nil {
				c.SetUserContext(appgateway.WithGateway(c.UserContext(), gw))
			}
			return c.Next()
		},
		guard.Middleware(),
		func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusOK)
		},
	)
	return app
}

func hybridGuardGet(t *testing.T, app *fiber.App) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/route", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	return resp
}

func gatewayWithDataPlane(dataPlane string) *gatewaydomain.Gateway {
	return &gatewaydomain.Gateway{Entitlements: gatewaydomain.Entitlements{
		Tier:      gatewaydomain.TierFree,
		DataPlane: dataPlane,
	}}
}

func TestHybridGatewayGuard_RejectsHybridGatewayOnHostedProxy(t *testing.T) {
	app := newHybridGuardApp(t, false, gatewayWithDataPlane(gatewaydomain.DataPlaneHybrid))

	resp := hybridGuardGet(t, app)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, fiber.StatusMisdirectedRequest, resp.StatusCode)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body httpio.ErrorBody
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, middleware.ErrCodeHybridGateway, body.Error)
}

func TestHybridGatewayGuard_ServesHybridGatewayOnHybridDataPlane(t *testing.T) {
	app := newHybridGuardApp(t, true, gatewayWithDataPlane(gatewaydomain.DataPlaneHybrid))

	resp := hybridGuardGet(t, app)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestHybridGatewayGuard_ServesHostedGateways(t *testing.T) {
	for name, dataPlane := range map[string]string{
		"empty":  "",
		"hosted": gatewaydomain.DataPlaneHosted,
	} {
		t.Run(name, func(t *testing.T) {
			app := newHybridGuardApp(t, false, gatewayWithDataPlane(dataPlane))

			resp := hybridGuardGet(t, app)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		})
	}
}

func TestHybridGatewayGuard_PassesWhenGatewayNotResolved(t *testing.T) {
	app := newHybridGuardApp(t, false, nil)

	resp := hybridGuardGet(t, app)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}
