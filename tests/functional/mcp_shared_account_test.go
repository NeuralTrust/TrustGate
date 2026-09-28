//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

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

func requireRPCSucceeded(t *testing.T, status int, body map[string]any) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, status)
	rpcErr, present := body["error"]
	require.False(t, present && rpcErr != nil, "the rpc call must not answer with an error")
	result, _ := body["result"].(map[string]any)
	return result
}

// mcpSharedRegistryPayload is the same forwarded instance, set to hold one
// account for every caller instead of one per caller.
func mcpSharedRegistryPayload(name, upstreamURL, provider string, idp *oauthProviderStub) map[string]any {
	payload := mcpForwardedRegistryPayload(name, upstreamURL, provider, idp)
	target, _ := payload["mcp_target"].(map[string]any)
	auth, _ := target["auth"].(map[string]any)
	auth["account"] = "shared"
	return payload
}

// sharedAccountConnectLink is the admin's side of the link: the ticket is minted
// against the instance, not against whoever will call it.
func sharedAccountConnectLink(t *testing.T, gatewayID, registryID string) string {
	t.Helper()
	target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/shared-account/connect-link", AdminURL, gatewayID, registryID)
	status, body := sendRequest(t, http.MethodPost, target, nil, nil)
	require.Equal(t, http.StatusOK, status, "mint shared-account connect link failed: %v", body)
	ticket, _ := body["ticket"].(string)
	require.NotEmpty(t, ticket, "the connect link must carry a ticket: %v", body)
	return ticket
}

func sharedAccountStatus(t *testing.T, gatewayID, registryID string) map[string]any {
	t.Helper()
	target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/shared-account", AdminURL, gatewayID, registryID)
	status, body := sendRequest(t, http.MethodGet, target, nil, nil)
	require.Equal(t, http.StatusOK, status, "read shared account failed: %v", body)
	return body
}

// requireNotConnected is the refusal a machine caller gets instead of a connect
// ticket: it carries no capability, because nobody calling could redeem one.
func requireNotConnected(t *testing.T, status int, body map[string]any) string {
	t.Helper()
	require.Equal(t, http.StatusOK, status)
	rpcErr, ok := body["error"].(map[string]any)
	require.True(t, ok, "expected a refusal, got %v", body)
	require.Equal(t, float64(-32003), rpcErr["code"])
	message, _ := rpcErr["message"].(string)
	require.NotContains(t, message, "ticket=", "a refusal must not hand out a connect ticket")
	require.Nil(t, rpcErr["data"], "a refusal carries no connect url")
	return message
}

type forwardedFixture struct {
	idp                             *oauthProviderStub
	capture                         *upstreamCapture
	gatewayID, provider, registryID string
}

func (fx forwardedFixture) echoToolCall() map[string]any {
	return map[string]any{"name": exposedToolName(fx.registryID, "echo"), "arguments": map[string]any{"message": "hola"}}
}

func newForwardedFixture(t *testing.T, shared bool) forwardedFixture {
	t.Helper()
	idp := newOAuthProviderStub(t)
	upstream, capture := startCapturingMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID, provider := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")}), uniqueName("prov")
	name := uniqueName("mcp-reg")
	payload := mcpForwardedRegistryPayload(name, upstream.URL, provider, idp)
	if shared {
		payload = mcpSharedRegistryPayload(name, upstream.URL, provider, idp)
	}
	registryID := CreateRegistry(t, gatewayID, payload)
	return forwardedFixture{idp: idp, capture: capture, gatewayID: gatewayID, provider: provider, registryID: registryID}
}

// The account belongs to the instance: an admin connects it once, out of band,
// and every call the gateway forwards to that server rides on it.
func TestMCPSharedAccount_ForwardedFlowEndToEnd(t *testing.T) {
	fx := newForwardedFixture(t, true)
	consumerID, key := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")

	t.Run("before the admin connects it, the call is refused and says who fixes it", func(t *testing.T) {
		status, body := mcpRPC(t, fx.gatewayID, consumerID, apiKeyHeaders(key), "tools/call", fx.echoToolCall())
		message := requireNotConnected(t, status, body)
		require.Contains(t, message, "administrator")
		_, seen := fx.capture.observed()
		require.Zero(t, seen, "an unconnected instance must not reach the upstream")
	})

	t.Run("the admin walks the connect page with the ticket pinned to the instance", func(t *testing.T) {
		driveProviderConsent(t, fx.idp, fx.provider, sharedAccountConnectLink(t, fx.gatewayID, fx.registryID))
		params, authorized := fx.idp.authorizeParams()
		require.True(t, authorized, "the provider authorize endpoint must be reached")
		require.Equal(t, "S256", params.Get("code_challenge_method"))
		require.NotEmpty(t, params.Get("code_challenge"))

		account := sharedAccountStatus(t, fx.gatewayID, fx.registryID)
		require.Equal(t, true, account["connected"], "the instance must report its account: %v", account)
		require.Equal(t, fx.provider, account["provider"])
	})

	// What a client reads before it starts, and the same fact the runtime acts
	// on. A batch that gates on this endpoint and then calls the server must not
	// be told two different things about the same account: reporting the
	// instance's connected account as "not connected" stops a run that would
	// have worked, and no caller can do anything about it.
	t.Run("the connections endpoint reports the instance's account", func(t *testing.T) {
		connections := appConnections(t, fx.gatewayID, consumerID, key)
		require.NotEmpty(t, connections, "a forwarded server is a connectable one")
		found := false
		for _, connection := range connections {
			if connection["provider"] != fx.provider {
				continue
			}
			found = true
			require.Equal(t, "connected", connection["status"],
				"the admin connected this instance's account: %v", connection)
		}
		require.True(t, found, "the bound server must be listed: %v", connections)
	})

	t.Run("the stored credential is injected into the upstream call", func(t *testing.T) {
		fx.capture.reset()
		status, body := mcpRPC(t, fx.gatewayID, consumerID, apiKeyHeaders(key), "tools/call", fx.echoToolCall())
		raw, err := json.Marshal(requireRPCSucceeded(t, status, body))
		require.NoError(t, err)
		require.Contains(t, string(raw), "echo:hola")

		last, seen := fx.capture.observed()
		require.GreaterOrEqual(t, seen, 1, "the upstream must have been called")
		requireBearerMatches(t, fx.idp.bearer(), last)
		require.Equal(t, 1, fx.idp.tokenExchanges(), "the injected bearer must come from the vault, not from a refresh exchange")
	})
}

// One account, every application: that is what "shared" means, and it is the
// difference from the per-caller account the same instance holds when it is set
// to `user`. Two applications bound to one shared instance both reach the
// upstream on the account the admin connected, without a second consent.
func TestMCPSharedAccount_ServesEveryApplication(t *testing.T) {
	fx := newForwardedFixture(t, true)
	consumerA, keyA := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")
	consumerB, keyB := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")
	secondAuthID, secondKeyOfA := CreateAPIKeyAuth(t, fx.gatewayID, uniqueName("mcp-key"))
	AttachAuth(t, fx.gatewayID, consumerA, secondAuthID)

	driveProviderConsent(t, fx.idp, fx.provider, sharedAccountConnectLink(t, fx.gatewayID, fx.registryID))

	for _, caller := range []struct {
		name       string
		consumerID string
		key        string
	}{
		{name: "the application the admin had in mind", consumerID: consumerA, key: keyA},
		{name: "another credential of that application", consumerID: consumerA, key: secondKeyOfA},
		{name: "a different application on the same instance", consumerID: consumerB, key: keyB},
	} {
		t.Run(caller.name, func(t *testing.T) {
			fx.capture.reset()
			status, body := mcpRPC(t, fx.gatewayID, caller.consumerID, apiKeyHeaders(caller.key), "tools/call", fx.echoToolCall())
			requireRPCSucceeded(t, status, body)
			bearer, seen := fx.capture.observed()
			require.GreaterOrEqual(t, seen, 1, "the caller must reach the upstream")
			requireBearerMatches(t, fx.idp.bearer(), bearer)
			require.Equal(t, 1, fx.idp.tokenExchanges(), "the instance's account is connected once, for everyone")
		})
	}
}

// The other half of the rule: an instance whose accounts are per caller has
// nothing for a request that runs as the application itself, because there is
// no person behind it to walk a consent page. It is told so, with both remedies,
// and is never handed a ticket it could not redeem.
func TestMCPUserInstance_RefusesARequestThatRunsAsTheApplication(t *testing.T) {
	fx := newForwardedFixture(t, false)
	consumerID, key := createMCPConsumer(t, fx.gatewayID, []string{fx.registryID}, nil, "")

	status, body := mcpRPC(t, fx.gatewayID, consumerID, apiKeyHeaders(key), "tools/call", fx.echoToolCall())
	message := requireNotConnected(t, status, body)
	require.Contains(t, message, "end user")
	require.Contains(t, message, "shared account")

	_, seen := fx.capture.observed()
	require.Zero(t, seen, "a refused call must not reach the upstream")

	// And there is no shared account to read on it either: whose account this
	// instance uses is answered per caller, so the question does not apply.
	target := fmt.Sprintf("%s/v1/gateways/%s/registries/%s/shared-account", AdminURL, fx.gatewayID, fx.registryID)
	status, body = sendRequest(t, http.MethodGet, target, nil, nil)
	require.Equal(t, http.StatusConflict, status, "a user instance has no shared account: %v", body)
}

// appConnections is GET /{slug}/connections with no end_user: what the
// application itself has connected, which is the preflight a batch runs.
func appConnections(t *testing.T, gatewayID, consumerID, key string) []map[string]any {
	t.Helper()
	slug := ConsumerSlug(t, consumerID)
	req, err := http.NewRequest(http.MethodGet, MCPURL+"/"+slug+"/connections", nil)
	require.NoError(t, err)
	req.Host = mcpHostOf(t, gatewayID)
	req.Header.Set("X-AG-API-Key", key)
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	require.Equal(t, "application", body["actor"])
	raw, _ := body["connections"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if connection, ok := item.(map[string]any); ok {
			out = append(out, connection)
		}
	}
	return out
}

// mcpHostOf is the host the gateway's MCP plane answers on.
func mcpHostOf(t *testing.T, gatewayID string) string {
	t.Helper()
	host, ok := mcpHosts.Load(gatewayID)
	require.True(t, ok, "mcp host missing for %s", gatewayID)
	return host.(string)
}
