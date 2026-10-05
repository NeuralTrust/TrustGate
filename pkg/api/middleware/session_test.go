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
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	gwmocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	sessionmocks "github.com/NeuralTrust/TrustGate/pkg/app/session/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testGatewayID        = "11111111-1111-1111-1111-111111111111"
	defaultSessionHeader = "X-Session-Id"

	pathChatCompletions = "/team/v1/chat/completions"
	pathResponses       = "/team/v1/responses"
)

type sessionCapture struct {
	session   infracontext.Session
	found     bool
	effective string
}

func (c *sessionCapture) id() string { return c.session.ID }

func (c *sessionCapture) generated() bool { return c.found && c.session.Generated() }

type sessionAppOption func(*sessionAppConfig)

type sessionAppConfig struct {
	store *sessionmocks.Store
}

func withStore(store *sessionmocks.Store) sessionAppOption {
	return func(c *sessionAppConfig) { c.store = store }
}

func newSessionApp(t *testing.T, gw *domain.Gateway, opts ...sessionAppOption) (*fiber.App, *sessionCapture) {
	t.Helper()
	cfg := &sessionAppConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	finder := gwmocks.NewFinder(t)
	gwID := ids.From[ids.GatewayKind](uuid.MustParse(testGatewayID))
	if gw != nil {
		finder.EXPECT().FindByID(mock.Anything, gwID).Return(gw, nil).Maybe()
	}
	store := cfg.store
	if store == nil {
		store = sessionmocks.NewStore(t)
	}
	mw := middleware.NewSessionMiddleware(slog.New(slog.NewTextHandler(io.Discard, nil)), finder, store)

	capt := &sessionCapture{}
	app := fiber.New()
	if gw != nil {
		app.Use(func(c *fiber.Ctx) error {
			c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gwID))
			return c.Next()
		})
	}
	app.Post("/*", mw.Middleware(), func(c *fiber.Ctx) error {
		capt.session, capt.found = infracontext.SessionFromContext(c.UserContext())
		capt.effective = middleware.EffectiveSessionID(c)
		return c.SendStatus(fiber.StatusOK)
	})
	return app, capt
}

func gatewayWithSession(cfg *domain.SessionConfig) *domain.Gateway {
	return &domain.Gateway{ID: ids.From[ids.GatewayKind](uuid.MustParse(testGatewayID)), Slug: "gw", SessionConfig: cfg}
}

func boolPtr(b bool) *bool { return &b }

func doRequest(t *testing.T, app *fiber.App, body string, headers map[string]string) *http.Response {
	t.Helper()
	return doPathRequest(t, app, pathChatCompletions, body, headers)
}

func doPathRequest(t *testing.T, app *fiber.App, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, path, strings.NewReader(body))
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
	require.True(t, capt.generated())
	requireValidUUID(t, capt.id())
	require.Equal(t, capt.id(), resp.Header.Get(defaultSessionHeader))
}

func TestSession_NoConfig_Generates(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doRequest(t, app, `{}`, nil)
	require.True(t, capt.generated())
	requireValidUUID(t, capt.id())
	require.Equal(t, capt.id(), resp.Header.Get(defaultSessionHeader))
}

func TestSession_Disabled_Passthrough(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(false), HeaderName: defaultSessionHeader}))
	resp := doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "abc"})
	require.False(t, capt.found)
	require.Empty(t, capt.effective)
	require.Empty(t, resp.Header.Get(defaultSessionHeader))
}

func TestSession_ConfigWithoutEnabled_DefaultsOn(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{HeaderName: defaultSessionHeader}))
	resp := doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "sess-header"})
	require.Equal(t, "sess-header", capt.effective)
	require.False(t, capt.generated())
	require.Equal(t, "sess-header", resp.Header.Get(defaultSessionHeader))
}

func TestSession_DefaultHeader(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "sess-default"})
	require.Equal(t, "sess-default", capt.effective)
	require.Equal(t, infracontext.SessionSourceConfiguredHeader, capt.session.Source)
	require.Equal(t, "sess-default", resp.Header.Get(defaultSessionHeader))
}

// The configured header keeps accepting the short ids existing deployments send.
func TestSession_ConfiguredHeaderAcceptsShortIDs(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "a"})
	require.Equal(t, "a", capt.effective)
}

func TestSession_ConfiguredHeaderRejectsOverlongIDs(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{
		defaultSessionHeader: strings.Repeat("a", 257),
		"X-TG-Session-Id":    "sess-fallback",
	})
	require.Equal(t, "sess-fallback", capt.effective)
}

func TestSession_FromCustomHeader(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: "X-Custom-Session"}))
	resp := doRequest(t, app, `{}`, map[string]string{"X-Custom-Session": "sess-header"})
	require.Equal(t, "sess-header", capt.effective)
	require.False(t, capt.generated())
	require.Equal(t, "sess-header", resp.Header.Get(defaultSessionHeader))
}

// With a custom configured header, X-Session-Id becomes one of the well-known
// headers (opencode sends it) and is validated as such.
func TestSession_XSessionIDIsWellKnownWhenNotConfigured(t *testing.T) {
	cfg := &domain.SessionConfig{Enabled: boolPtr(true), HeaderName: "X-Custom-Session"}

	app, capt := newSessionApp(t, gatewayWithSession(cfg))
	doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "opencode-session-1"})
	require.Equal(t, "opencode-session-1", capt.effective)
	require.Equal(t, infracontext.SessionSourceKnownHeader, capt.session.Source)

	app, capt = newSessionApp(t, gatewayWithSession(cfg))
	doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: "short"})
	require.Equal(t, "short", capt.effective, "X-Session-Id is the default header everywhere, so it keeps the lenient check")
}

func TestSession_WellKnownHeaders(t *testing.T) {
	for _, header := range []string{
		"X-TG-Session-Id",
		"X-OpenWebUI-Chat-Id",
		"X-Claude-Code-Session-Id",
		"session_id",
		"session-id",
		"x-session-affinity",
		"Helicone-Session-Id",
		"x-litellm-session-id",
		"x-litellm-trace-id",
	} {
		t.Run(header, func(t *testing.T) {
			app, capt := newSessionApp(t, gatewayWithSession(nil))
			resp := doRequest(t, app, `{}`, map[string]string{header: "conv-0123456789"})
			require.Equal(t, "conv-0123456789", capt.effective)
			require.Equal(t, infracontext.SessionSourceKnownHeader, capt.session.Source)
			require.Equal(t, "conv-0123456789", resp.Header.Get(defaultSessionHeader))
		})
	}
}

func TestSession_WellKnownHeadersFollowTheListOrder(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{
		"x-litellm-trace-id":       "litellm-trace-1",
		"X-Claude-Code-Session-Id": "claude-code-1",
		"X-OpenWebUI-Chat-Id":      "openwebui-chat-1",
	})
	require.Equal(t, "openwebui-chat-1", capt.effective)
}

func TestSession_WellKnownHeaderValidation(t *testing.T) {
	cases := map[string]string{
		"too short":       "abc1234",
		"too long":        strings.Repeat("a", 257),
		"space":           "conv 0123456789",
		"slash":           "conv/0123456789",
		"non ascii":       "conversación-1",
		"quote":           `conv"0123456789`,
		"percent encoded": "conv%200123456",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			app, capt := newSessionApp(t, gatewayWithSession(nil))
			doRequest(t, app, `{}`, map[string]string{
				"X-Claude-Code-Session-Id": value,
				"Helicone-Session-Id":      "helicone-session-1",
			})
			require.Equal(t, "helicone-session-1", capt.effective, "an invalid value falls through to the next source")
		})
	}
}

// The headers read before the well-known list grew keep accepting any value, so
// an existing client's short or free-form id is never silently dropped.
func TestSession_LegacyKnownHeadersStayLenient(t *testing.T) {
	cases := map[string]string{
		"X-TG-Session-Id":     "abc",
		"X-OpenWebUI-Chat-Id": "chat 42/ünïcode",
	}
	for header, value := range cases {
		t.Run(header, func(t *testing.T) {
			app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: "X-Custom-Session"}))
			doRequest(t, app, `{}`, map[string]string{header: value})
			require.Equal(t, value, capt.effective)
		})
	}
}

func TestSession_IDsUpTo256CharactersAreAccepted(t *testing.T) {
	long := strings.Repeat("a", 256)
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{defaultSessionHeader: long})
	require.Equal(t, long, capt.effective)
}

func TestSession_WellKnownHeaderAcceptsTheFullCharset(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	id := "Ab9._:-" + strings.Repeat("z", 121)
	doRequest(t, app, `{}`, map[string]string{"X-TG-Session-Id": id})
	require.Equal(t, id, capt.effective)
}

func TestSession_VendorSessionHeaderPattern(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{"X-Acme-Agent-Session-Id": "acme-session-1"})
	require.Equal(t, "acme-session-1", capt.effective)
	require.Equal(t, infracontext.SessionSourcePatternHeader, capt.session.Source)
}

func TestSession_VendorSessionHeadersAreTriedInNameOrder(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{
		"X-Zeta-Session-Id":  "zeta-session-1",
		"X-Beta-Session-Id":  "bad",
		"X-Alpha-Session-Id": "alpha-session-1",
	})
	require.Equal(t, "alpha-session-1", capt.effective)

	app, capt = newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{
		"X-Zeta-Session-Id": "zeta-session-1",
		"X-Beta-Session-Id": "bad",
	})
	require.Equal(t, "zeta-session-1", capt.effective, "an invalid vendor header is skipped")
}

func TestSession_WellKnownHeaderBeatsVendorPattern(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{}`, map[string]string{
		"X-Aaa-Session-Id":   "aaa-session-1",
		"x-litellm-trace-id": "litellm-trace-1",
	})
	require.Equal(t, "litellm-trace-1", capt.effective)
}

func TestSession_VendorPatternNeedsAVendor(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: "X-Custom-Session"}))
	doRequest(t, app, `{}`, map[string]string{"X-Sessionx-Id": "not-a-session-1", "X-Session-Ids": "not-a-session-2"})
	require.True(t, capt.generated())
}

// An explicit configuration is a deliberate choice and outranks a guess.
func TestSession_ConfiguredHeaderBeatsKnownChatHeader(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: "X-Custom-Session"}))
	doRequest(t, app, `{}`, map[string]string{
		"X-Custom-Session":    "sess-configured",
		"X-OpenWebUI-Chat-Id": "chat-abc-1",
	})
	require.Equal(t, "sess-configured", capt.effective)
}

func TestSession_KnownChatHeaderBeatsBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, map[string]string{"X-OpenWebUI-Chat-Id": "chat-abc-1"})
	require.Equal(t, "chat-abc-1", capt.effective)
}

func TestSession_FromBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, nil)
	require.Equal(t, "sess-body", capt.effective)
	require.Equal(t, infracontext.SessionSourceBodyField, capt.session.Source)
}

func TestSession_FromGzipBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(`{"session_id":"sess-gzip"}`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	doRequest(t, app, buf.String(), map[string]string{"Content-Encoding": "gzip"})
	require.Equal(t, "sess-gzip", capt.effective)
}

func TestSession_BodyFieldRejectsControlCharacters(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess\u0000body"}`, nil)
	require.True(t, capt.generated())
}

func TestSession_HeaderTakesPrecedenceOverBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), HeaderName: defaultSessionHeader, BodyParamName: "session_id"}))
	doRequest(t, app, `{"session_id":"sess-body"}`, map[string]string{defaultSessionHeader: "sess-header"})
	require.Equal(t, "sess-header", capt.effective)
}

func TestSession_NoClientValue_Generates(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "session_id"}))
	resp := doRequest(t, app, `not-json`, nil)
	require.True(t, capt.generated())
	requireValidUUID(t, capt.id())
	require.Equal(t, capt.id(), resp.Header.Get(defaultSessionHeader))
}

// A generated id on a stateless chat request stands for nothing: it is echoed
// so the client can adopt it, but consumers must not count it as a session.
func TestSession_GeneratedIDIsHiddenOutsideResponses(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doRequest(t, app, `{"messages":[]}`, nil)
	require.True(t, capt.generated())
	require.False(t, capt.session.Exposed)
	require.Empty(t, capt.effective)
	require.Equal(t, capt.id(), resp.Header.Get(defaultSessionHeader))
}

func TestSession_GeneratedIDIsKeptForResponses(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doPathRequest(t, app, pathResponses, `{"input":"hi"}`, nil)
	require.True(t, capt.generated())
	require.True(t, capt.session.Exposed)
	requireValidUUID(t, capt.effective)
	require.Equal(t, capt.effective, resp.Header.Get(defaultSessionHeader))
}

func TestSession_ResponsesConversationString(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	resp := doPathRequest(t, app, pathResponses, `{"conversation":"conv_abc123","input":"hi"}`, nil)
	require.Equal(t, "conv_abc123", capt.effective)
	require.Equal(t, infracontext.SessionSourceConversation, capt.session.Source)
	require.Equal(t, "conv_abc123", resp.Header.Get(defaultSessionHeader))
}

func TestSession_ResponsesConversationObject(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doPathRequest(t, app, pathResponses, `{"conversation":{"id":"conv_obj456"},"input":"hi"}`, nil)
	require.Equal(t, "conv_obj456", capt.effective)
}

func TestSession_ResponsesConversationIgnoredOnOtherFormats(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doRequest(t, app, `{"conversation":"conv_abc123"}`, nil)
	require.True(t, capt.generated())
}

func TestSession_ResponsesInvalidConversationFallsThrough(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doPathRequest(t, app, pathResponses, `{"conversation":{"id":"bad id"},"input":"hi"}`, nil)
	require.True(t, capt.generated())
}

func TestSession_ResponsesPreviousResponseHit(t *testing.T) {
	store := sessionmocks.NewStore(t)
	store.EXPECT().SessionForTurn(mock.Anything, testGatewayID, "resp_prev1").Return("sess-chain").Once()
	app, capt := newSessionApp(t, gatewayWithSession(nil), withStore(store))
	resp := doPathRequest(t, app, pathResponses, `{"previous_response_id":"resp_prev1","input":"next"}`, nil)
	require.Equal(t, "sess-chain", capt.effective)
	require.Equal(t, infracontext.SessionSourcePreviousResponse, capt.session.Source)
	require.Equal(t, "sess-chain", resp.Header.Get(defaultSessionHeader))
}

func TestSession_ResponsesPreviousResponseMissGeneratesAKeptID(t *testing.T) {
	store := sessionmocks.NewStore(t)
	store.EXPECT().SessionForTurn(mock.Anything, testGatewayID, "resp_expired").Return("").Once()
	app, capt := newSessionApp(t, gatewayWithSession(nil), withStore(store))
	doPathRequest(t, app, pathResponses, `{"previous_response_id":"resp_expired","input":"next"}`, nil)
	require.True(t, capt.generated())
	require.NotEmpty(t, capt.effective)
}

func TestSession_ResponsesConversationBeatsPreviousResponse(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doPathRequest(t, app, pathResponses, `{"conversation":"conv_abc123","previous_response_id":"resp_prev1"}`, nil)
	require.Equal(t, "conv_abc123", capt.effective)
}

// The client's explicit ids always win over anything inferred from the body,
// and no store lookup happens when a header already named the session.
func TestSession_HeaderBeatsResponsesBody(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(nil))
	doPathRequest(t, app, pathResponses,
		`{"conversation":"conv_abc123","previous_response_id":"resp_prev1"}`,
		map[string]string{"X-Claude-Code-Session-Id": "claude-code-1"})
	require.Equal(t, "claude-code-1", capt.effective)

	app, capt = newSessionApp(t, gatewayWithSession(nil))
	doPathRequest(t, app, pathResponses, `{"previous_response_id":"resp_prev1"}`, map[string]string{defaultSessionHeader: "s1"})
	require.Equal(t, "s1", capt.effective)
}

func TestSession_BodyFieldBeatsResponsesConversation(t *testing.T) {
	app, capt := newSessionApp(t, gatewayWithSession(&domain.SessionConfig{Enabled: boolPtr(true), BodyParamName: "user_session"}))
	doPathRequest(t, app, pathResponses, `{"user_session":"sess-body","conversation":"conv_abc123"}`, nil)
	require.Equal(t, "sess-body", capt.effective)
}
