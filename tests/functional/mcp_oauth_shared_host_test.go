//go:build functional

package functional_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// sharedHost is a hostname that is NOT a per-gateway subdomain
// ({slug}.<base>). The MCP plane resolves the consumer from the path alone, so
// the OAuth facade must work here exactly as it does behind a dedicated
// subdomain: this is the "shared host" access pattern (a single MCP ingress in
// front of every gateway, with the consumer slug carried in the path).
const sharedHost = "trustgate-mcp.shared.neuraltrust.ai"

// oauthIDPStub is an upstream identity provider that serves enough OAuth 2.0
// authorization-server metadata for the gateway to build a redirect, plus a
// JWKS document. The gateway process reaches it over the loopback interface.
type oauthIDPStub struct {
	server *httptest.Server
	issuer string
}

func newOAuthIDPStub(t *testing.T) *oauthIDPStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	stub := &oauthIDPStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 stub.issuer,
			"authorization_endpoint": stub.issuer + "/authorize",
			"token_endpoint":         stub.issuer + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "kid-1",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	stub.server = httptest.NewServer(mux)
	stub.issuer = stub.server.URL
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *oauthIDPStub) jwksURL() string { return s.server.URL + "/jwks" }

func (s *oauthIDPStub) host(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(s.server.URL)
	require.NoError(t, err)
	return u.Host
}

func oauth2AuthPayload(name, issuer, jwksURL, audience, clientID, scope string) map[string]any {
	return map[string]any{
		"name":    name,
		"type":    "oauth2",
		"enabled": true,
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":          issuer,
				"audiences":       []string{audience},
				"jwks_url":        jwksURL,
				"client_id":       clientID,
				"required_scopes": []string{scope},
			},
		},
	}
}

// noRedirectClient never follows redirects so the test can inspect the 302
// Location the authorize endpoint returns.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// mcpRequestWithHost issues a request to the MCP plane while pinning the Host
// header to host, mirroring how an ingress forwards a shared-host request to
// the MCP pod. Redirects are not followed.
func mcpRequestWithHost(t *testing.T, method, path, host string, query url.Values, body any) *http.Response {
	t.Helper()
	target := MCPURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, target, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Host = host
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &out), "body: %s", string(raw))
	}
	return out
}

func authorizeQuery(clientID, resource string) url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://client.example/oauth/callback")
	q.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	q.Set("code_challenge_method", "S256")
	q.Set("state", "state-"+uniqueName("s"))
	if resource != "" {
		q.Set("resource", resource)
	}
	return q
}

// TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP locks in the
// shared-host OAuth flow: when two identity providers exist on the gateway, the
// per-path RFC 8707 resource the challenge induces is what lets a request that
// arrives over a generic host (not the per-gateway subdomain) resolve the
// single IdP bound to the consumer, instead of failing with invalid_target.
func TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP(t *testing.T) {
	upstream := startMCPUpstream(t, func(s *sdk.Server) { addTool(s, "echo") })
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("mcp-gw")})
	registryID := CreateRegistry(t, gatewayID, mcpRegistryPayload(uniqueName("mcp-reg"), upstream.URL))

	// Two issuers => gateway-wide selection is ambiguous; only the resource can
	// disambiguate.
	idpA := newOAuthIDPStub(t)
	idpB := newOAuthIDPStub(t)
	clientA := "client-" + strings.ToLower(uniqueName("a"))
	authA := CreateAuth(t, gatewayID, oauth2AuthPayload(
		uniqueName("idp-a"), idpA.issuer, idpA.jwksURL(),
		"mcp-"+strings.ToLower(uniqueName("aud")), clientA, "mcp.read"))
	_ = CreateAuth(t, gatewayID, oauth2AuthPayload(
		uniqueName("idp-b"), idpB.issuer, idpB.jwksURL(),
		"mcp-"+strings.ToLower(uniqueName("aud")), "client-"+strings.ToLower(uniqueName("b")), "mcp.write"))

	roleID := CreateRole(t, gatewayID, map[string]any{
		"name": uniqueName("mcp-role"),
		"oidc_mapping": map[string]any{
			"match": "any",
			"claims": []map[string]any{
				{"path": "groups", "op": "contains_any", "values": []string{"mcp-users"}},
			},
		},
	})
	AttachRoleRegistry(t, gatewayID, roleID, registryID)
	consumerID := CreateConsumer(t, gatewayID, map[string]any{
		"name":         uniqueName("mcp-rb-consumer"),
		"type":         "mcp",
		"routing_mode": "role_based",
		"roles":        []string{roleID},
	})
	AttachAuth(t, gatewayID, consumerID, authA)

	slug := ConsumerSlug(t, consumerID)
	mcpPath := "/" + slug + "/mcp"
	prmPath := "/.well-known/oauth-protected-resource/" + slug + "/mcp"
	baseURL := "http://" + sharedHost
	wantResource := baseURL + "/" + slug + "/mcp"

	t.Run("challenge is scoped to the consumer path", func(t *testing.T) {
		resp := mcpRequestWithHost(t, http.MethodPost, mcpPath, sharedHost, nil,
			map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Equal(t,
			`Bearer resource_metadata="`+baseURL+prmPath+`"`,
			resp.Header.Get("WWW-Authenticate"))
	})

	t.Run("protected-resource metadata echoes the path-scoped resource", func(t *testing.T) {
		resp := mcpRequestWithHost(t, http.MethodGet, prmPath, sharedHost, nil, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		meta := decodeBody(t, resp)
		require.Equal(t, wantResource, meta["resource"])
		servers, ok := meta["authorization_servers"].([]any)
		require.True(t, ok, "authorization_servers missing: %v", meta)
		require.Contains(t, servers, baseURL)
	})

	t.Run("authorize without a resource is ambiguous", func(t *testing.T) {
		resp := mcpRequestWithHost(t, http.MethodGet, "/oauth/authorize", sharedHost,
			authorizeQuery(clientA, ""), nil)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, "invalid_target", decodeBody(t, resp)["error"])
	})

	t.Run("authorize with the path-scoped resource redirects to the consumer IdP", func(t *testing.T) {
		// The attached credential reaches the MCP process only after the admin
		// plane's cache-invalidation event propagates via Redis, so poll until
		// the resource resolves to IdP A.
		require.Eventually(t, func() bool {
			resp := mcpRequestWithHost(t, http.MethodGet, "/oauth/authorize", sharedHost,
				authorizeQuery(clientA, wantResource), nil)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusFound {
				return false
			}
			loc, err := resp.Location()
			return err == nil && loc.Host == idpA.host(t)
		}, 5*time.Second, 100*time.Millisecond,
			"authorize must redirect to the consumer's IdP once the credential propagates")
	})
}
