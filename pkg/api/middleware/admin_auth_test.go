package middleware_test

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func newAdminAuthApp(t *testing.T, secret string) (*fiber.App, jwt.Manager) {
	t.Helper()
	mgr := jwt.NewJwtManager(&config.ServerConfig{SecretKey: secret})
	mw := middleware.NewAdminAuthMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), mgr)

	app := fiber.New()
	app.Get("/protected", mw.Middleware(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app, mgr
}

func TestAdminAuth_MissingHeader(t *testing.T) {
	app, _ := newAdminAuthApp(t, "secret")
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/protected", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAdminAuth_InvalidFormat(t *testing.T) {
	app, _ := newAdminAuthApp(t, "secret")
	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Token abc")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAdminAuth_InvalidToken(t *testing.T) {
	app, _ := newAdminAuthApp(t, "secret")
	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAdminAuth_ValidToken(t *testing.T) {
	app, mgr := newAdminAuthApp(t, "secret")
	token, err := mgr.CreateToken()
	require.NoError(t, err)

	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAdminAuth_WrongSecretRejected(t *testing.T) {
	otherMgr := jwt.NewJwtManager(&config.ServerConfig{SecretKey: "other"})
	token, err := otherMgr.CreateToken()
	require.NoError(t, err)

	app, _ := newAdminAuthApp(t, "secret")
	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}
