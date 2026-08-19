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
	"net/url"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authsession "github.com/NeuralTrust/TrustGate/pkg/infra/auth/session"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/golang-jwt/jwt/v5"
)

type httpUserInfo struct{ client *http.Client }

func (h httpUserInfo) Fetch(ctx context.Context, userInfoURL, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	var info map[string]any
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&info); err != nil {
		return nil, err
	}
	return info, nil
}

// githubLikeIdP stubs an opaque-token IdP: a form-encoded token endpoint with no
// JWT access_token and a GitHub-shaped userinfo endpoint returning a numeric id.
func githubLikeIdP(t *testing.T, userID int) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
			})
		case "/token":
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = w.Write([]byte("access_token=gho_opaque&token_type=bearer&scope=mcp.access"))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": userID, "login": "octocat"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func githubSessionProxy(t *testing.T, idpURL string, signer *infrasts.Signer, chainer ConsentChainer) AuthProxy {
	t.Helper()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{
			Issuer:         idpURL,
			ClientID:       "gw-client-id",
			SessionMode:    true,
			UserInfoURL:    idpURL + "/user",
			SubjectClaim:   "id",
			Audiences:      []string{"api://gw"},
			RequiredScopes: []string{"mcp.access"},
		}),
	}}
	return NewAuthProxy(finder, nil, http.DefaultClient, newMemFlowStore(), chainer, signer, httpUserInfo{http.DefaultClient})
}

func exchangeCodeFrom(t *testing.T, resumeURL string) string {
	t.Helper()
	u, err := url.Parse(resumeURL)
	if err != nil {
		t.Fatalf("parse resume URL: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("parked resume URL carries no gateway code: %s", resumeURL)
	}
	return code
}

// AC#1 + AC#2: an opaque GitHub-style IdP yields a gateway-minted session JWT
// that verifies against the gateway JWKS, and the subject captured at Callback
// (the consent vault-write key) equals the verified principal subject (the
// vault-read key on MCP requests) — parity by construction.
func TestSessionFlowGitHubOpaqueEndToEnd(t *testing.T) {
	t.Parallel()
	idp := githubLikeIdP(t, 12345)
	signer := newTestSigner(t)
	chainer := &fakeChainer{url: "http://gw.example.com/v1/mcp/github/connect?ticket=tk"}
	proxy := githubSessionProxy(t, idp.URL, signer, chainer)
	ctx := context.Background()

	gwState := authorizeAndGetState(t, proxy, "")
	detour, err := proxy.Callback(ctx, "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if detour != chainer.url {
		t.Fatalf("expected consent detour, got %s", detour)
	}
	if chainer.calls != 1 || chainer.sub != "12345" {
		t.Fatalf("consent detour must fire once with the captured subject, calls=%d sub=%q", chainer.calls, chainer.sub)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         exchangeCodeFrom(t, chainer.resume),
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	access, _ := resp["access_token"].(string)
	if access == "" {
		t.Fatal("expected a minted session access_token")
	}

	verifier, err := authsession.NewVerifier(signer)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	principal, err := verifier.Verify(ctx, access)
	if err != nil {
		t.Fatalf("minted token must verify against the gateway JWKS: %v", err)
	}
	if principal.Subject != "12345" {
		t.Fatalf("verified subject must equal the captured subject, got %q", principal.Subject)
	}
	if use, _ := principal.Claims["token_use"].(string); use != "mcp_session" {
		t.Fatalf("expected token_use=mcp_session, got %q", use)
	}
	if chainer.sub != principal.Subject {
		t.Fatalf("vault write-key %q must equal read-key %q", chainer.sub, principal.Subject)
	}
}

// AC#2: distinct upstream identities mint distinct, non-colliding subjects.
func TestSessionFlowDistinctSubjectsDoNotCollide(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	verifier, err := authsession.NewVerifier(signer)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	ctx := context.Background()

	mint := func(userID int) *jwtPrincipalSubject {
		idp := githubLikeIdP(t, userID)
		proxy := githubSessionProxy(t, idp.URL, signer, &fakeChainer{url: ""})
		gwState := authorizeAndGetState(t, proxy, "")
		clientLoc, err := proxy.Callback(ctx, "http://gw.example.com", gwState, "idp-code", "", "")
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
			GrantType:    "authorization_code",
			Code:         exchangeCodeFrom(t, clientLoc),
			RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
			CodeVerifier: "client-verifier",
		})
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		principal, err := verifier.Verify(ctx, resp["access_token"].(string))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return &jwtPrincipalSubject{subject: principal.Subject, token: resp["access_token"].(string)}
	}

	a := mint(12345)
	b := mint(67890)
	if a.subject != "12345" || b.subject != "67890" {
		t.Fatalf("subjects must follow the upstream id, got %q and %q", a.subject, b.subject)
	}
	if a.subject == b.subject || a.token == b.token {
		t.Fatalf("distinct identities must not collide: %q vs %q", a.subject, b.subject)
	}
}

type jwtPrincipalSubject struct {
	subject string
	token   string
}

// AC#3: with SessionMode off (Okta), exchange returns the IdP JWT verbatim and
// the gateway adds no session refresh_token — byte-for-byte pass-through.
func TestOktaFlowNoRegressionEndToEnd(t *testing.T) {
	t.Parallel()
	idpJWT := unsignedJWT(t, map[string]any{"sub": "okta-user", "iss": "https://okta.example.com"})
	idp := fakeIdPWithToken(t, idpJWT)
	proxy := chainProxyUnderTest(t, idp.URL, newMemFlowStore(), &fakeChainer{url: ""})
	ctx := context.Background()

	gwState := authorizeAndGetState(t, proxy, "")
	clientLoc, err := proxy.Callback(ctx, "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         exchangeCodeFrom(t, clientLoc),
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp["access_token"] != idpJWT {
		t.Fatalf("OFF mode must return the IdP token verbatim, got %v", resp["access_token"])
	}
	if _, ok := resp["refresh_token"]; ok {
		t.Fatalf("OFF mode must not mint a gateway refresh_token, got %v", resp)
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(idpJWT, claims); err != nil {
		t.Fatalf("returned token must remain the IdP JWT: %v", err)
	}
	if iss, _ := claims.GetIssuer(); iss != "https://okta.example.com" {
		t.Fatalf("subject must derive from the IdP token, got issuer %q", iss)
	}
}

// githubNoDiscoveryIdP models real GitHub: the authorization-server metadata
// paths 404, only the fixed login/token endpoints and a GitHub-shaped userinfo
// endpoint respond.
func githubNoDiscoveryIdP(t *testing.T, userID int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = w.Write([]byte("access_token=gho_opaque&token_type=bearer&scope=read:user"))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": userID, "login": "octocat"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// GitHub publishes no authorization-server discovery, so the inbound oauth2
// auth pins authorize_url/token_url explicitly. Authorize must redirect to the
// pinned endpoint without any discovery call, and the opaque login must still
// mint a verifiable gateway session token.
func TestSessionFlowGitHubExplicitEndpointsNoDiscovery(t *testing.T) {
	t.Parallel()
	idp := githubNoDiscoveryIdP(t, 4242)
	signer := newTestSigner(t)
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{
			Issuer:         "https://github.com",
			ClientID:       "gw-client-id",
			ClientSecret:   "gw-secret",
			SessionMode:    true,
			UserInfoURL:    idp.URL + "/user",
			SubjectClaim:   "id",
			Audiences:      []string{"api://gw"},
			RequiredScopes: []string{"read:user"},
			AuthorizeURL:   idp.URL + "/login/oauth/authorize",
			TokenURL:       idp.URL + "/login/oauth/access_token",
		}),
	}}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, newMemFlowStore(), &fakeChainer{url: ""}, signer, httpUserInfo{http.DefaultClient})
	ctx := context.Background()

	location, err := proxy.Authorize(ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "gw-client-id",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if base := loc.Scheme + "://" + loc.Host + loc.Path; base != idp.URL+"/login/oauth/authorize" {
		t.Fatalf("authorize must redirect to the pinned endpoint, got %s", base)
	}

	clientLoc, err := proxy.Callback(ctx, "http://gw.example.com", loc.Query().Get("state"), "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         exchangeCodeFrom(t, clientLoc),
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	access, _ := resp["access_token"].(string)
	if access == "" {
		t.Fatal("expected a minted session access_token")
	}
	verifier, err := authsession.NewVerifier(signer)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	principal, err := verifier.Verify(ctx, access)
	if err != nil {
		t.Fatalf("minted token must verify against the gateway JWKS: %v", err)
	}
	if principal.Subject != "4242" {
		t.Fatalf("subject must follow the GitHub id, got %q", principal.Subject)
	}
}
