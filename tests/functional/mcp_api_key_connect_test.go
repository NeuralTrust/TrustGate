//go:build functional

package functional_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

type oauthProviderStub struct {
	server         *httptest.Server
	mu             sync.Mutex
	codes          map[string]struct{}
	accessToken    string
	refreshedToken string
	refreshToken   string
	tokenCalls     int
	authorizeCalls int
	lastAuthorize  url.Values
}

func newOAuthProviderStub(t *testing.T) *oauthProviderStub {
	t.Helper()
	stub := &oauthProviderStub{
		codes:          map[string]struct{}{},
		accessToken:    "access-" + uniqueName("t"),
		refreshedToken: "refreshed-" + uniqueName("t"),
		refreshToken:   "refresh-" + uniqueName("r"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", stub.handleAuthorize)
	mux.HandleFunc("/token", stub.handleToken)
	stub.server = httptest.NewServer(mux)
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *oauthProviderStub) authorizeURL() string { return s.server.URL + "/authorize" }

func (s *oauthProviderStub) tokenURL() string { return s.server.URL + "/token" }

func (s *oauthProviderStub) host(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(s.server.URL)
	require.NoError(t, err)
	return u.Host
}

func (s *oauthProviderStub) bearer() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "Bearer " + s.accessToken
}

func (s *oauthProviderStub) refreshedBearer() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return "Bearer " + s.refreshedToken
}

func (s *oauthProviderStub) tokenExchanges() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls
}

func (s *oauthProviderStub) authorizeParams() (url.Values, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.lastAuthorize), s.authorizeCalls > 0
}

func (s *oauthProviderStub) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	state := query.Get("state")
	redirectURI := query.Get("redirect_uri")
	code := "code-" + uniqueName("c")

	s.mu.Lock()
	s.lastAuthorize = query
	s.authorizeCalls++
	s.mu.Unlock()

	if state == "" || redirectURI == "" {
		writeProviderError(w, "invalid_request")
		return
	}
	target, err := url.Parse(redirectURI)
	if err != nil {
		writeProviderError(w, "invalid_request")
		return
	}

	s.mu.Lock()
	s.codes[code] = struct{}{}
	s.mu.Unlock()

	forwarded := target.Query()
	forwarded.Set("code", code)
	forwarded.Set("state", state)
	target.RawQuery = forwarded.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *oauthProviderStub) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeProviderError(w, "invalid_request")
		return
	}
	var refreshed bool
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		if !s.consumeCode(r.PostForm.Get("code")) {
			writeProviderError(w, "invalid_grant")
			return
		}
	case "refresh_token":
		if !s.matchesRefreshToken(r.PostForm.Get("refresh_token")) {
			writeProviderError(w, "invalid_grant")
			return
		}
		refreshed = true
	default:
		writeProviderError(w, "unsupported_grant_type")
		return
	}

	s.mu.Lock()
	s.tokenCalls++
	access, refresh := s.accessToken, s.refreshToken
	if refreshed {
		access = s.refreshedToken
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "mcp.read",
	})
}

func (s *oauthProviderStub) consumeCode(code string) bool {
	if code == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.codes[code]; !ok {
		return false
	}
	delete(s.codes, code)
	return true
}

func (s *oauthProviderStub) matchesRefreshToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return token != "" && token == s.refreshToken
}

func writeProviderError(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": reason})
}

type upstreamCapture struct {
	mu   sync.Mutex
	last string
	seen int
}

func (c *upstreamCapture) record(authorization string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = authorization
	c.seen++
}

func (c *upstreamCapture) observed() (string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.seen
}

func (c *upstreamCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = ""
	c.seen = 0
}

func startCapturingMCPUpstream(t *testing.T, configure func(*sdk.Server)) (*httptest.Server, *upstreamCapture) {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "fake-upstream", Version: "1.0"}, nil)
	if configure != nil {
		configure(server)
	}
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
	capture := &upstreamCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.record(r.Header.Get("Authorization"))
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, capture
}

func mcpForwardedRegistryPayload(name, upstreamURL, provider string, idp *oauthProviderStub) map[string]any {
	return map[string]any{
		"name":   name,
		"type":   "mcp",
		"weight": 1,
		"mcp_target": map[string]any{
			"url": upstreamURL,
			"auth": map[string]any{
				"mode":          "forwarded",
				"registration":  "manual",
				"provider":      provider,
				"client_id":     "client-" + provider,
				"authorize_url": idp.authorizeURL(),
				"token_url":     idp.tokenURL(),
				"scopes":        []string{"mcp.read"},
			},
		},
	}
}

func gatewayHostOf(t *testing.T, gatewayID string) string {
	t.Helper()
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	return host.(string)
}

func mcpConnectFormPost(t *testing.T, path, host string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, MCPURL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = host
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	return resp
}

func doRedacted(t *testing.T, target, stage string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("%s request could not be built", stage)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("%s request failed", stage)
	}
	return resp
}

func connectTicketFrom(t *testing.T, resp *http.Response, slug string) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	loc, err := resp.Location()
	require.NoError(t, err)
	require.Equal(t, "/"+slug+"/mcp/connect", loc.Path)
	ticket := loc.Query().Get("ticket")
	require.NotEmpty(t, ticket)
	return ticket
}

func driveProviderConsent(t *testing.T, idp *oauthProviderStub, provider, ticket string) {
	t.Helper()
	started := doRedacted(t, MCPURL+"/oauth/connect/"+provider+"?ticket="+url.QueryEscape(ticket), "connect start")
	authorize, err := started.Location()
	_ = started.Body.Close()
	require.Equal(t, http.StatusFound, started.StatusCode)
	require.NoError(t, err)
	require.Equal(t, idp.host(t), authorize.Host)
	require.Equal(t, MCPURL+"/oauth/callback/"+provider, authorize.Query().Get("redirect_uri"))

	consented := doRedacted(t, authorize.String(), "provider authorize")
	callback, err := consented.Location()
	_ = consented.Body.Close()
	require.Equal(t, http.StatusFound, consented.StatusCode)
	require.NoError(t, err)
	require.Equal(t, "/oauth/callback/"+provider, callback.Path)
	require.NotEmpty(t, callback.Query().Get("code"))
	require.NotEmpty(t, callback.Query().Get("state"))

	finished := doRedacted(t, callback.String(), "connect callback")
	_ = finished.Body.Close()
	require.Equal(t, http.StatusOK, finished.StatusCode)
}

func requireBearerMatches(t *testing.T, want, got string) {
	t.Helper()
	require.True(t, strings.HasPrefix(got, "Bearer "), "upstream authorization must be a bearer token (len=%d)", len(got))
	require.True(t, got == want,
		"upstream bearer must equal the token minted by the provider stub (want len=%d, got len=%d)", len(want), len(got))
}

func requireConsentRequired(t *testing.T, status int, body map[string]any) {
	t.Helper()
	require.Equal(t, http.StatusOK, status)
	rpcErr, ok := body["error"].(map[string]any)
	require.True(t, ok, "expected a consent-required rpc error")
	require.Equal(t, float64(-32003), rpcErr["code"])
}

func requireRPCSucceeded(t *testing.T, status int, body map[string]any) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, status)
	rpcErr, present := body["error"]
	require.False(t, present && rpcErr != nil, "the rpc call must not answer with an error")
	result, _ := body["result"].(map[string]any)
	return result
}

func requireConnectPageReachable(t *testing.T, path, host string) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp := mcpRequestWithHost(t, http.MethodGet, path, host, nil, nil)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 100*time.Millisecond, "the api-key connect page must become reachable once the consumer propagates")
}

func echoToolCall() map[string]any {
	return map[string]any{"name": "echo", "arguments": map[string]any{"message": "hola"}}
}

type forwardedFixture struct {
	idp                             *oauthProviderStub
	capture                         *upstreamCapture
	gatewayID, provider, registryID string
}

func newForwardedFixture(t *testing.T) forwardedFixture {
	t.Helper()
	idp := newOAuthProviderStub(t)
	upstream, capture := startCapturingMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID, provider := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")}), uniqueName("prov")
	registryID := CreateRegistry(t, gatewayID, mcpForwardedRegistryPayload(uniqueName("mcp-reg"), upstream.URL, provider, idp))
	return forwardedFixture{idp: idp, capture: capture, gatewayID: gatewayID, provider: provider, registryID: registryID}
}

func TestMCPAPIKeyConnect_ForwardedFlowEndToEnd(t *testing.T) {
	require.False(t, GlobalConfig.MCPConnectRateLimit.Enabled)

	fx := newForwardedFixture(t)
	consumerID, key := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")

	slug := ConsumerSlug(t, consumerID)
	host := gatewayHostOf(t, fx.gatewayID)
	connectPath := "/" + slug + "/connect"
	var ticket string

	t.Run("connect page is reachable through the running MCP plane", func(t *testing.T) {
		requireConnectPageReachable(t, connectPath, host)
	})

	t.Run("api key is exchanged for a ticket", func(t *testing.T) {
		ticket = connectTicketFrom(t, mcpConnectFormPost(t, connectPath, host, url.Values{"api_key": {key}}), slug)
	})

	t.Run("consent completes against the fake provider", func(t *testing.T) {
		driveProviderConsent(t, fx.idp, fx.provider, ticket)
		params, authorized := fx.idp.authorizeParams()
		require.True(t, authorized, "the provider authorize endpoint must be reached")
		require.Equal(t, "S256", params.Get("code_challenge_method"))
		require.NotEmpty(t, params.Get("code_challenge"))
	})

	t.Run("stored credential is injected into the upstream call", func(t *testing.T) {
		status, body := mcpRPC(t, fx.gatewayID, consumerID, apiKeyHeaders(key), "tools/call", echoToolCall())
		raw, err := json.Marshal(requireRPCSucceeded(t, status, body))
		require.NoError(t, err)
		require.Contains(t, string(raw), "echo:hola")

		last, seen := fx.capture.observed()
		require.GreaterOrEqual(t, seen, 1, "the upstream must have been called")
		requireBearerMatches(t, fx.idp.bearer(), last)
		require.False(t, last == fx.idp.refreshedBearer(), "the injected bearer must come from the vault, not from a refresh exchange")
		require.Equal(t, 1, fx.idp.tokenExchanges())
	})
}

func TestMCPAPIKeyConnect_SharedKeyReusesGrantAndIsolatesPrincipals(t *testing.T) {
	require.False(t, GlobalConfig.MCPConnectRateLimit.Enabled)

	fx := newForwardedFixture(t)
	consumerA, keyA := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")
	_, foreignKey := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")
	otherAuthID, otherKey := CreateAPIKeyAuth(t, fx.gatewayID, uniqueName("mcp-key"))
	AttachAuth(t, fx.gatewayID, consumerA, otherAuthID)

	host := gatewayHostOf(t, fx.gatewayID)
	slugA := ConsumerSlug(t, consumerA)
	connectA := "/" + slugA + "/connect"
	requireConnectPageReachable(t, connectA, host)

	ticket := connectTicketFrom(t, mcpConnectFormPost(t, connectA, host, url.Values{"api_key": {keyA}}), slugA)
	driveProviderConsent(t, fx.idp, fx.provider, ticket)

	status, body := mcpRPC(t, fx.gatewayID, consumerA, apiKeyHeaders(keyA), "tools/call", echoToolCall())
	requireRPCSucceeded(t, status, body)

	fx.capture.reset()
	status, body = mcpRPC(t, fx.gatewayID, consumerA, apiKeyHeaders(keyA), "tools/call", echoToolCall())
	requireRPCSucceeded(t, status, body)
	sharedBearer, seen := fx.capture.observed()
	require.GreaterOrEqual(t, seen, 1, "a second client sharing the api key must reach the upstream")
	requireBearerMatches(t, fx.idp.bearer(), sharedBearer)
	require.Equal(t, 1, fx.idp.tokenExchanges(), "reusing the stored grant must not run consent again")

	fx.capture.reset()
	status, body = mcpRPC(t, fx.gatewayID, consumerA, apiKeyHeaders(otherKey), "tools/call", echoToolCall())
	requireConsentRequired(t, status, body)
	_, seenOther := fx.capture.observed()
	require.Zero(t, seenOther, "a second api-key principal must not reach the upstream on the first principal's grant")

	rejected := mcpConnectFormPost(t, connectA, host, url.Values{"api_key": {foreignKey}})
	defer func() { _ = rejected.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, rejected.StatusCode)
}
