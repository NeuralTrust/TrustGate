package middleware_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
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

func newAdminAuthAppWithLogger(t *testing.T, secret string, logger *slog.Logger) (*fiber.App, jwt.Manager) {
	t.Helper()
	mgr := jwt.NewJwtManager(&config.ServerConfig{SecretKey: secret})
	mw := middleware.NewAdminAuthMiddleware(logger, mgr)

	app := fiber.New()
	app.Get("/protected", mw.Middleware(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app, mgr
}

func decodeErrorBody(t *testing.T, resp *http.Response) helpers.ErrorBody {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body helpers.ErrorBody
	require.NoError(t, json.Unmarshal(data, &body))
	return body
}

func TestAdminAuth_MissingHeader(t *testing.T) {
	app, _ := newAdminAuthApp(t, "secret")
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/protected", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, helpers.ErrorBody{
		Error:   "unauthorized",
		Message: "Authorization required",
	}, decodeErrorBody(t, resp))
}

func TestAdminAuth_InvalidFormat(t *testing.T) {
	app, _ := newAdminAuthApp(t, "secret")
	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Token abc")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, helpers.ErrorBody{
		Error:   "unauthorized",
		Message: "Invalid authorization format",
	}, decodeErrorBody(t, resp))
}

func TestAdminAuth_InvalidToken(t *testing.T) {
	app, _ := newAdminAuthApp(t, "secret")
	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	require.Equal(t, helpers.ErrorBody{
		Error:   "unauthorized",
		Message: "Invalid token",
	}, decodeErrorBody(t, resp))
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

func TestAdminAuth_AuthFailureLoggedAtDebug(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	app, _ := newAdminAuthAppWithLogger(t, "secret", logger)

	req := httptest.NewRequest(fiber.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	req.Header.Set(fiber.HeaderXRequestID, "req-123")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	logOutput := logs.String()
	require.True(t, strings.Contains(logOutput, "level=DEBUG"), logOutput)
	require.True(t, strings.Contains(logOutput, "msg=\"admin auth failed\""), logOutput)
	require.True(t, strings.Contains(logOutput, "reason=\"Invalid token\""), logOutput)
	require.True(t, strings.Contains(logOutput, "request_id=req-123"), logOutput)
}
