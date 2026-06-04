package fingerprint_test

import (
	"net/http/httptest"
	"testing"

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func captureFingerprint(t *testing.T, setup func(*fiber.Ctx)) fingerprint.Fingerprint {
	t.Helper()
	tracker := fingerprint.NewFingerPrintTracker()
	app := fiber.New()
	var captured fingerprint.Fingerprint
	app.Get("/", func(c *fiber.Ctx) error {
		setup(c)
		captured = tracker.MakeFingerprint(c)
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	return captured
}

func TestMakeFingerprint_KeepsClientSession(t *testing.T) {
	fp := captureFingerprint(t, func(c *fiber.Ctx) {
		c.Locals(string(infracontext.SessionContextKey), "sess-client")
	})
	require.Equal(t, "sess-client", fp.SessionID)
}

func TestMakeFingerprint_IgnoresGeneratedSession(t *testing.T) {
	fp := captureFingerprint(t, func(c *fiber.Ctx) {
		c.Locals(string(infracontext.SessionContextKey), "sess-generated")
		c.Locals(string(infracontext.SessionGeneratedContextKey), true)
	})
	require.Empty(t, fp.SessionID, "gateway-generated session ids must not feed the fingerprint")
}
