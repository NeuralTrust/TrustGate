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
	"io"
	"log/slog"
	"net/http"
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

const (
	testGatewayID        = "11111111-1111-1111-1111-111111111111"
	defaultSessionHeader = "X-Session-Id"
)

type sessionCapture struct {
	sessionID string
	generated bool
}

func newSessionApp(t *testing.T, gw *domain.Gateway) (*fiber.App, *sessionCapture) {
	t.Helper()
	finder := gwmocks.NewFinder(t)
	gwID := ids.From[ids.GatewayKind](uuid.MustParse(testGatewayID))
	if gw != nil {
		finder.EXPECT().FindByID(mock.Anything, gwID).Return(gw, nil).Maybe()
	}
	mw := middleware.NewSessionMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), finder)

	capt := &sessionCapture{}
	app := fiber.New()
	if gw != nil {
		app.Use(func(c *fiber.Ctx) error {
			c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gwID))
			return c.Next()
		})
	}
	app.Post("/", mw.Middleware(), func(c *fiber.Ctx) error {
		if v, ok := c.UserContext().Value(infracontext.SessionContextKey).(string); ok {
			capt.sessionID = v
		}
		if v, ok := c.Locals(string(infracontext.SessionContextKey)).(string); ok && capt.sessionID == "" {
			capt.sessionID = v
		}
		if v, ok := c.UserContext().Value(infracontext.SessionGeneratedContextKey).(bool); ok && v {
			capt.generated = true
		}
		return c.SendStatus(fiber.StatusOK)
	})
	return app, capt
}

func gatewayWithSession(cfg *domain.SessionConfig) *domain.Gateway {
	return &domain.Gateway{ID: ids.From[ids.GatewayKind](uuid.MustParse(testGatewayID)), Name: "gw", SessionConfig: cfg}
}

func boolPtr(b bool) *bool { return &b }

func doRequest(t *testing.T, app *fiber.App, body string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	return resp
}

func requireValidUUID(t *testing.T, s string) {
	t.Helper()
	require.NotEmpty(t, s)
	_, err := uuid.Parse(s)
	require.NoError(t, err)
}

func TestSession_NoGatewayInContext_Generates(t *testing.T) {
	app, capt := newSessionApp(t, nil)
	resp := doRequest(t, app, `{}`, nil)
	require.True(t, capt.generated)
	requireValidUUID(t, capt.sessionID)
	require.Equal(t, capt.sessionID, resp.Header.Get(defaultSessionHeader))
}

func TestSession_NoConfig_Generates(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doRequest(t, app, `{}`, nil)
	require.True(t, capt.generated)
	requireValidUUID(t, capt.sessionID)
	require.Equal(t, capt.sessionID, resp.Header.Get(defaultSessionHeader))
}

func TestSession_Disabled_Passthrough(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(false), HeaderName: defaultSessionHeader}))
	resp := doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "abc"})
	require.Empty(t, capt.sessionID)
	require.False(t, capt.generated)
	require.Empty(t, resp.Header.Get(defaultSessionHeader))
}

func TestSession_ConfigWithoutEnabled_DefaultsOn(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{HeaderName: defaultSessionHeader}))
	resp := doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "sess-header"})
	require.Equal(t, "sess-header", capt.sessionID)
	require.False(t, capt.generated)
	require.Equal(t, "sess-header", resp.Header.Get(defaultSessionHeader))
}

func TestSession_DefaultHeader(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "sess-default"})
	require.Equal(t, "sess-default", capt.sessionID)
	require.False(t, capt.generated)
	require.Equal(t, "sess-default", resp.Header.Get(defaultSessionHeader))
}

func TestSession_FromCustomHeader(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: "X-Custom-Session"}))
	resp := doRequest(t, app, `{}`, map[string]string{"X-Custom-Session": "sess-header"})
	require.Equal(t, "sess-header", capt.sessionID)
	require.False(t, capt.generated)
	require.Equal(t, "sess-header", resp.Header.Get(defaultSessionHeader))
}

func TestSession_FromBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, nil)
	require.Equal(t, "sess-body", capt.sessionID)
	require.False(t, capt.generated)
}

func TestSession_HeaderTakesPrecedenceOverBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: defaultSessionHeader, BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, map[string]string{defaultSessionHeader: "sess-header"})
	require.Equal(t, "sess-header", capt.sessionID)
	require.False(t, capt.generated)
}

func TestSession_NoClientValue_Generates(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	resp := doRequest(t, app, `not-json`, nil)
	require.True(t, capt.generated)
	requireValidUUID(t, capt.sessionID)
	require.Equal(t, capt.sessionID, resp.Header.Get(defaultSessionHeader))
}
