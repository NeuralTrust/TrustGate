package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestFingerPrintMiddleware_StampsID(t *testing.T) {
	mw := middleware.NewFingerPrintMiddleware(fingerprint.NewFingerPrintTracker())

	var stampedLocal string
	var stampedCtx string
	app := fiber.New()
	app.Get("/", mw.Middleware(), func(c *fiber.Ctx) error {
		if v, ok := c.Locals(string(infracontext.FingerprintIDContextKey)).(string); ok {
			stampedLocal = v
		}
		if v, ok := c.UserContext().Value(infracontext.FingerprintIDContextKey).(string); ok {
			stampedCtx = v
		}
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token-123")
	req.Header.Set("X-User-ID", "user-1")
	req.Header.Set("User-Agent", "test-agent/1.0")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	require.NotEmpty(t, stampedLocal)
	require.Equal(t, stampedLocal, stampedCtx)

	fp, err := fingerprint.NewFromID(stampedLocal)
	require.NoError(t, err)
	require.Equal(t, "user-1", fp.UserID)
	require.Equal(t, "token-123", fp.Token)
}
