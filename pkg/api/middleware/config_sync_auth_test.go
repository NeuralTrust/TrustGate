package middleware_test

import (
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/gofiber/fiber/v2"
)

func newConfigSyncApp(token string) *fiber.App {
	return newConfigSyncAppWithPrevious(token, "")
}

func newConfigSyncAppWithPrevious(token, previous string) *fiber.App {
	cfg := &config.Config{}
	cfg.ConfigSync.Token = token
	cfg.ConfigSync.TokenPrevious = previous
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

func TestConfigSyncAuthTokenRotation(t *testing.T) {
	app := newConfigSyncAppWithPrevious("current-token", "previous-token")

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"current accepted", "Bearer current-token", fiber.StatusOK},
		{"previous accepted", "Bearer previous-token", fiber.StatusOK},
		{"unknown rejected", "Bearer stale-token", fiber.StatusUnauthorized},
		{"missing rejected", "", fiber.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status := requestStatus(t, app, tc.header); status != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, status)
			}
		})
	}
}
