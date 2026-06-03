package middleware_test

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	gwmocks "github.com/NeuralTrust/AgentGateway/pkg/app/gateway/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testGatewayID = "11111111-1111-1111-1111-111111111111"

// newSessionApp builds a fiber app whose session middleware reads the gateway
// from the request context. When gw is non-nil, a preceding middleware injects
// the gateway id onto the context exactly as the auth middleware would; when it
// is nil, nothing is injected so the session middleware sees no gateway.
func newSessionApp(t *testing.T, gw *domain.Gateway) (*fiber.App, *string) {
	t.Helper()
	finder := gwmocks.NewFinder(t)
	gwID := ids.From[ids.GatewayKind](uuid.MustParse(testGatewayID))
	if gw != nil {
		finder.EXPECT().FindByID(mock.Anything, gwID).Return(gw, nil).Maybe()
	}
	mw := middleware.NewSessionMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), finder)

	captured := new(string)
	app := fiber.New()
	if gw != nil {
		app.Use(func(c *fiber.Ctx) error {
			c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gwID))
			return c.Next()
		})
	}
	app.Post("/", mw.Middleware(), func(c *fiber.Ctx) error {
		if v, ok := c.UserContext().Value(infracontext.SessionContextKey).(string); ok {
			*captured = v
		}
		if v, ok := c.Locals(string(infracontext.SessionContextKey)).(string); ok && *captured == "" {
			*captured = v
		}
		return c.SendStatus(fiber.StatusOK)
	})
	return app, captured
}

func gatewayWithSession(cfg *domain.SessionConfig) *domain.Gateway {
	return &domain.Gateway{ID: ids.From[ids.GatewayKind](uuid.MustParse(testGatewayID)), Name: "gw", SessionConfig: cfg}
}

func doRequest(t *testing.T, app *fiber.App, body string, headers map[string]string) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestSession_NoGatewayInContext_Passthrough(t *testing.T) {
	app, captured := newSessionApp(t, nil)
	doRequest(t, app, `{}`, nil)
	require.Empty(t, *captured)
}

func TestSession_NoConfig_Passthrough(t *testing.T) {
	app, captured := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, nil)
	require.Empty(t, *captured)
}

func TestSession_Disabled_Passthrough(t *testing.T) {
	app, captured := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: false, HeaderName: "X-Session-Id"}))
	doRequest(t, app, `{}`, map[string]string{"X-Session-Id": "abc"})
	require.Empty(t, *captured)
}

func TestSession_FromHeader(t *testing.T) {
	app, captured := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: true, HeaderName: "X-Session-Id"}))
	doRequest(t, app, `{}`, map[string]string{"X-Session-Id": "sess-header"})
	require.Equal(t, "sess-header", *captured)
}

func TestSession_FromBody(t *testing.T) {
	app, captured := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: true, BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, nil)
	require.Equal(t, "sess-body", *captured)
}

func TestSession_HeaderTakesPrecedenceOverBody(t *testing.T) {
	app, captured := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: true, HeaderName: "X-Session-Id", BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, map[string]string{"X-Session-Id": "sess-header"})
	require.Equal(t, "sess-header", *captured)
}

func TestSession_InvalidJSONBody_Passthrough(t *testing.T) {
	app, captured := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: true, BodyParamName: "session_id"}))
	doRequest(t, app, `not-json`, nil)
	require.Empty(t, *captured)
}
