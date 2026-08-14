//go:build functional

package functional_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
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
