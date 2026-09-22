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

package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type endUserGatewayResolver struct{ gw *gatewaydomain.Gateway }

func (r endUserGatewayResolver) Resolve(*fiber.Ctx) (*gatewaydomain.Gateway, error) { return r.gw, nil }

type stubEndUserConnections struct {
	link        *appoauth.EndUserLink
	connections []appoauth.EndUserConnection
	appAccounts []appoauth.EndUserConnection
	err         error
	appErr      error
	gotKey      string
	gotEndUser  string
	gotProvider string
	askedForApp bool
}

func (s *stubEndUserConnections) Link(_ context.Context, _ ids.GatewayID, _, rawKey, endUser, provider string) (*appoauth.EndUserLink, error) {
	s.gotKey, s.gotEndUser, s.gotProvider = rawKey, endUser, provider
	return s.link, s.err
}

func (s *stubEndUserConnections) Connections(_ context.Context, _ ids.GatewayID, _, rawKey, endUser string) ([]appoauth.EndUserConnection, error) {
	s.gotKey, s.gotEndUser = rawKey, endUser
	return s.connections, s.err
}

func (s *stubEndUserConnections) AppConnections(_ context.Context, _ ids.GatewayID, _, rawKey string) ([]appoauth.EndUserConnection, error) {
	s.gotKey, s.askedForApp = rawKey, true
	return s.appAccounts, s.appErr
}

func newEndUserApp(svc appoauth.EndUserConnectionsService) *fiber.App {
	h := NewEndUserConnectionsHandler(
		endUserGatewayResolver{gw: &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}},
		svc, appoauth.NewNoopConnectAttemptLimiter(), func(string, string) string { return "127.0.0.1" },
	)
	app := fiber.New()
	app.Post("/:slug/connections/links", h.Link)
	app.Get("/:slug/connections", h.List)
	return app
}

func TestEndUserConnectionsHandler_LinkReturnsConnectURL(t *testing.T) {
	expires := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	svc := &stubEndUserConnections{link: &appoauth.EndUserLink{Ticket: "t-1", Provider: "github", ExpiresAt: expires}}
	app := newEndUserApp(svc)

	req := httptest.NewRequest(fiber.MethodPost, "/assistant/connections/links", strings.NewReader(`{"end_user":"user_123","provider":"github"}`))
	req.Host = "acme.mcp.test"
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	req.Header.Set("X-AG-API-Key", "ag_secret")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusCreated, resp.StatusCode)
	require.Equal(t, "ag_secret", svc.gotKey)
	require.Equal(t, "user_123", svc.gotEndUser)
	require.Equal(t, "github", svc.gotProvider)

	var body EndUserLinkResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "http://acme.mcp.test/oauth/connect/github?ticket=t-1", body.ConnectURL)
	require.Equal(t, "t-1", body.Ticket)
	require.True(t, expires.Equal(body.ExpiresAt))
}

func TestEndUserConnectionsHandler_LinkWithoutProviderOpensConnectPage(t *testing.T) {
	svc := &stubEndUserConnections{link: &appoauth.EndUserLink{Ticket: "t 2"}}
	app := newEndUserApp(svc)
	req := httptest.NewRequest(fiber.MethodPost, "/assistant/connections/links", strings.NewReader(`{"end_user":"user_123"}`))
	req.Host = "acme.mcp.test"
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	req.Header.Set("X-AG-API-Key", "ag_secret")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusCreated, resp.StatusCode)
	raw, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(raw), `"connect_url":"http://acme.mcp.test/assistant/mcp/connect?ticket=t+2"`)
}

func TestEndUserConnectionsHandler_ErrorMapping(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"wrong key":                {appoauth.ErrAPIKeyConnectUnauthorized, fiber.StatusUnauthorized},
		"unknown provider":         {appoauth.ErrUnknownConnectProvider, fiber.StatusBadRequest},
		"rate limiter unavailable": {appoauth.ErrConnectRateLimitUnavailable, fiber.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			app := newEndUserApp(&stubEndUserConnections{err: tc.err})
			req := httptest.NewRequest(fiber.MethodGet, "/assistant/connections?end_user=user_123", nil)
			req.Host = "acme.mcp.test"
			req.Header.Set("X-AG-API-Key", "ag_secret")
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

func TestEndUserConnectionsHandler_ListReportsStates(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	svc := &stubEndUserConnections{connections: []appoauth.EndUserConnection{
		{Provider: "github", Registry: "GitHub", Code: "github", Status: appoauth.ConnectionConnected, AccountRef: "octocat", ExpiresAt: expires},
		{Provider: "notion", Registry: "Notion", Code: "notion", Status: appoauth.ConnectionNotConnected},
	}}
	app := newEndUserApp(svc)
	req := httptest.NewRequest(fiber.MethodGet, "/assistant/connections?end_user=user_123", nil)
	req.Host = "acme.mcp.test"
	req.Header.Set("X-AG-API-Key", "ag_secret")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	var body EndUserConnectionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "user_123", body.EndUser)
	require.Len(t, body.Connections, 2)
	require.Equal(t, "connected", body.Connections[0].Status)
	require.NotNil(t, body.Connections[0].ExpiresAt)
	require.Equal(t, "not_connected", body.Connections[1].Status)
	require.Nil(t, body.Connections[1].ExpiresAt)
}

// A batch has nobody to hand a connect link to once it is running, so it has to
// be able to ask beforehand whether its own accounts are good. Leaving end_user
// out is that question: the other actor, same endpoint.
func TestEndUserConnectionsHandler_ListWithoutEndUserAnswersForTheApplication(t *testing.T) {
	svc := &stubEndUserConnections{appAccounts: []appoauth.EndUserConnection{
		{Provider: "com.notion/mcp", Registry: "notion", Status: appoauth.ConnectionConnected, AccountRef: "ops@corp.com"},
		{Provider: "app.linear/mcp", Registry: "linear", Status: appoauth.ConnectionNotConnected},
	}}
	app := newEndUserApp(svc)

	request := httptest.NewRequest(http.MethodGet, "/jobs/connections", nil)
	request.Header.Set("Authorization", "Bearer key-1")
	response, err := app.Test(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, fiber.StatusOK, response.StatusCode)

	var body EndUserConnectionsResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	require.True(t, svc.askedForApp, "no end user was named, so the application is the actor")
	require.Equal(t, "application", body.Actor,
		"an empty end_user must not read as an unnamed user")
	require.Empty(t, body.EndUser)
	require.Len(t, body.Connections, 2)
	require.Equal(t, appoauth.ConnectionNotConnected, body.Connections[1].Status,
		"the run has to see the server it cannot call yet")
}

// Naming a user still asks the question it always did.
func TestEndUserConnectionsHandler_ListWithEndUserStillAnswersForTheUser(t *testing.T) {
	svc := &stubEndUserConnections{connections: []appoauth.EndUserConnection{
		{Provider: "com.notion/mcp", Status: appoauth.ConnectionConnected},
	}}
	app := newEndUserApp(svc)

	request := httptest.NewRequest(http.MethodGet, "/jobs/connections?end_user=user_123", nil)
	request.Header.Set("Authorization", "Bearer key-1")
	response, err := app.Test(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()

	var body EndUserConnectionsResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	require.False(t, svc.askedForApp)
	require.Equal(t, "user_123", svc.gotEndUser)
	require.Equal(t, "end_user", body.Actor)
	require.Equal(t, "user_123", body.EndUser)
}

// Both actors belong to every MCP consumer now: the application itself, and
// whoever it names on a request. So asking about one never means the other is
// unavailable, and the two conflicts that used to say so are gone.
func TestEndUserConnectionsHandler_ServesBothActorsOfOneConsumer(t *testing.T) {
	svc := &stubEndUserConnections{}
	app := newEndUserApp(svc)

	asApp := httptest.NewRequest(http.MethodGet, "/assistant/connections", nil)
	asApp.Header.Set("Authorization", "Bearer key-1")
	appResponse, err := app.Test(asApp)
	require.NoError(t, err)
	defer func() { _ = appResponse.Body.Close() }()
	require.Equal(t, fiber.StatusOK, appResponse.StatusCode)
	require.True(t, svc.askedForApp)

	forUser := httptest.NewRequest(http.MethodGet, "/assistant/connections?end_user=user_123", nil)
	forUser.Header.Set("Authorization", "Bearer key-1")
	userResponse, err := app.Test(forUser)
	require.NoError(t, err)
	defer func() { _ = userResponse.Body.Close() }()
	require.Equal(t, fiber.StatusOK, userResponse.StatusCode)
	require.Equal(t, "user_123", svc.gotEndUser)
}
