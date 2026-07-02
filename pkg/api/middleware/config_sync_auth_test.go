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
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/gofiber/fiber/v2"
)

func newConfigSyncApp(token string) *fiber.App {
	cfg := &config.Config{}
	cfg.ConfigSync.Token = token
	m := middleware.NewConfigSyncAuthMiddleware(cfg, nil)
	app := fiber.New()
	app.Get("/snapshot", m.Middleware(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func requestStatus(t *testing.T, app *fiber.App, authHeader string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "/snapshot", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp.StatusCode
}

func TestConfigSyncAuthAllowsValidToken(t *testing.T) {
	app := newConfigSyncApp("secret-token")
	if status := requestStatus(t, app, "Bearer secret-token"); status != fiber.StatusOK {
		t.Fatalf("expected 200 for valid token, got %d", status)
	}
}

func TestConfigSyncAuthRejectsInvalidToken(t *testing.T) {
	app := newConfigSyncApp("secret-token")
	if status := requestStatus(t, app, "Bearer wrong-token"); status != fiber.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", status)
	}
}

func TestConfigSyncAuthRejectsMissingToken(t *testing.T) {
	app := newConfigSyncApp("secret-token")
	if status := requestStatus(t, app, ""); status != fiber.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", status)
	}
}

func TestConfigSyncAuthFailsClosedWhenUnset(t *testing.T) {
	app := newConfigSyncApp("")
	if status := requestStatus(t, app, "Bearer anything"); status != fiber.StatusUnauthorized {
		t.Fatalf("expected 401 when token unset, got %d", status)
	}
}
