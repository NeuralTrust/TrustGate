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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/golang-jwt/jwt/v5"
)

type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("session refresh must not call the IdP, got request to %s", r.URL)
	return nil, fmt.Errorf("no IdP calls allowed during session refresh")
}

type fakeUserInfo struct {
	gotURL   string
	gotToken string
	info     map[string]any
	err      error
	calls    int
}

func (f *fakeUserInfo) Fetch(_ context.Context, userInfoURL, accessToken string) (map[string]any, error) {
	f.calls++
	f.gotURL, f.gotToken = userInfoURL, accessToken
	return f.info, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestSigner(t *testing.T) *infrasts.Signer {
	t.Helper()
	signer, err := infrasts.NewSigner("https://gw.example.com/sts", "", discardLogger())
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

func signerPublicKey(t *testing.T, signer *infrasts.Signer) *rsa.PublicKey {
	t.Helper()
	jwks := signer.JWKS()
	keys, ok := jwks["keys"].([]map[string]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("unexpected JWKS shape: %v", jwks)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(keys[0]["n"].(string))
	if err != nil {
		t.Fatalf("decode modulus: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(keys[0]["e"].(string))
	if err != nil {
		t.Fatalf("decode exponent: %v", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
}

func TestCaptureSubjectIDTokenDefaultPrefersOID(t *testing.T) {
	t.Parallel()
	p := &authProxy{}
	token := map[string]any{
		"access_token": "opaque",
		"id_token":     unsignedJWT(t, map[string]any{"oid": "user-oid", "sub": "pairwise-sub"}),
	}
	sub, err := p.captureSubject(context.Background(), &authdomain.OAuth2Config{}, token)
	if err != nil {
		t.Fatalf("captureSubject: %v", err)
	}
	if sub != "user-oid" {
		t.Fatalf("expected oid-preferred subject, got %q", sub)
	}
}

func TestCaptureSubjectIDTokenExplicitClaim(t *testing.T) {
	t.Parallel()
	p := &authProxy{}
	token := map[string]any{
		"id_token": unsignedJWT(t, map[string]any{"oid": "user-oid", "sub": "pairwise-sub"}),
	}
	sub, err := p.captureSubject(context.Background(), &authdomain.OAuth2Config{SubjectClaim: "sub"}, token)
	if err != nil {
		t.Fatalf("captureSubject: %v", err)
	}
	if sub != "pairwise-sub" {
		t.Fatalf("expected explicit sub claim, got %q", sub)
	}
}

func TestCaptureSubjectUserInfoCoercesNumericID(t *testing.T) {
	t.Parallel()
	userinfo := &fakeUserInfo{info: map[string]any{"id": float64(583231), "login": "octocat"}}
	p := &authProxy{userinfo: userinfo}
	cfg := &authdomain.OAuth2Config{UserInfoURL: "https://api.github.com/user", SubjectClaim: "id"}
	token := map[string]any{"access_token": "gho_token"}

	sub, err := p.captureSubject(context.Background(), cfg, token)
	if err != nil {
		t.Fatalf("captureSubject: %v", err)
	}
	if sub != "583231" {
		t.Fatalf("expected numeric GitHub id coerced to string, got %q", sub)
	}
	if userinfo.gotURL != "https://api.github.com/user" || userinfo.gotToken != "gho_token" {
		t.Fatalf("userinfo fetched with wrong args: url=%q token=%q", userinfo.gotURL, userinfo.gotToken)
	}
}

func sessionAuth(t *testing.T, idpURL string) *authdomain.Auth {
	t.Helper()
	return oauth2Auth(t, authdomain.OAuth2Config{
		Issuer:       idpURL,
		ClientID:     "gw-client-id",
		SessionMode:  true,
		UserInfoURL:  "https://userinfo.example.com/user",
		SubjectClaim: "id",
		Audiences:    []string{"api://gw"},
	})
}

func TestCallbackSessionModeEmptySubjectDenied(t *testing.T) {
	t.Parallel()
	idp := fakeIdPWithToken(t, "opaque-token")
	store := newMemFlowStore()
	userinfo := &fakeUserInfo{info: map[string]any{"login": "octocat"}}
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{sessionAuth(t, idp.URL)}}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, store, nil, newTestSigner(t), userinfo)

	gwState := authorizeAndGetState(t, proxy, "")
	_, err := proxy.Callback(context.Background(), "http://gw.example.com", gwState, "idp-code", "", "")
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("expected access_denied for empty subject, got %v", err)
	}
	if userinfo.calls != 1 {
		t.Fatalf("expected userinfo to be consulted once, got %d", userinfo.calls)
	}
}

func TestExchangeCodeSessionModeMintsSessionToken(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, http.DefaultClient, store, nil, signer, nil)
	ctx := context.Background()

	if err := store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        "auth-1",
		GatewayID:     "gw-1",
		Audiences:     []string{"api://gw"},
		Scopes:        []string{"mcp.access", "openid"},
		SessionMode:   true,
	}); err != nil {
		t.Fatalf("save code: %v", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp["token_type"] != "Bearer" || resp["expires_in"] != 3600 {
		t.Fatalf("unexpected session token envelope: %v", resp)
	}
	if resp["scope"] != "mcp.access openid" {
		t.Fatalf("unexpected scope, got %v", resp["scope"])
	}
	refresh, _ := resp["refresh_token"].(string)
	if !strings.HasPrefix(refresh, "gwrt_") {
		t.Fatalf("expected a gwrt_-prefixed refresh_token, got %q", refresh)
	}
	access, _ := resp["access_token"].(string)
	if access == "" {
		t.Fatal("expected a minted access_token")
	}

	claims := jwt.MapClaims{}
	pub := signerPublicKey(t, signer)
	parsed, err := jwt.ParseWithClaims(access, claims, func(tok *jwt.Token) (any, error) {
		if tok.Method.Alg() != "RS256" {
			t.Fatalf("unexpected alg %s", tok.Method.Alg())
		}
		return pub, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("minted token must verify against the signer: %v", err)
	}
	if claims["sub"] != "user-42" || claims["token_use"] != "mcp_session" || claims["authid"] != "auth-1" {
		t.Fatalf("unexpected minted claims: %v", claims)
	}
	if claims["iss"] != signer.Issuer() {
		t.Fatalf("expected issuer %q, got %v", signer.Issuer(), claims["iss"])
	}

	rec := store.peekSession(refresh)
	if rec == nil {
		t.Fatal("SaveSession must persist a record")
	}
	if rec.Subject != "user-42" || strings.Join(rec.Scopes, " ") != "mcp.access openid" {
		t.Fatalf("session record mismatch: %+v", rec)
	}
}

func TestRefreshSessionReMintsAndRotates(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	noIdP := &http.Client{Transport: failingTransport{t}}
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, noIdP, store, nil, signer, nil)
	ctx := context.Background()

	const oldRefresh = "gwrt_old-refresh"
	if err := store.SaveSession(ctx, oldRefresh, SessionRecord{
		Subject:   "user-42",
		Scopes:    []string{"mcp.access", "openid"},
		GatewayID: "gw-1",
		AuthID:    "auth-1",
		Audiences: []string{"api://gw"},
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: oldRefresh,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if resp["token_type"] != "Bearer" || resp["expires_in"] != 3600 {
		t.Fatalf("unexpected session envelope: %v", resp)
	}
	if resp["scope"] != "mcp.access openid" {
		t.Fatalf("scopes must be preserved, got %v", resp["scope"])
	}

	newRefresh, _ := resp["refresh_token"].(string)
	if !strings.HasPrefix(newRefresh, "gwrt_") || newRefresh == oldRefresh {
		t.Fatalf("refresh_token must be rotated with the gwrt_ prefix, got %q", newRefresh)
	}
	rotated := store.peekSession(newRefresh)
	if rotated == nil {
		t.Fatal("rotated session must be persisted")
	}
	if rotated.Subject != "user-42" || strings.Join(rotated.Scopes, " ") != "mcp.access openid" {
		t.Fatalf("rotated record must preserve subject/scopes, got %+v", rotated)
	}

	if _, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: oldRefresh,
	}); err == nil {
		t.Fatal("old refresh_token must be single-use after rotation")
	} else {
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
			t.Fatalf("expected invalid_grant for a consumed refresh token, got %v", err)
		}
	}

	access, _ := resp["access_token"].(string)
	claims := jwt.MapClaims{}
	pub := signerPublicKey(t, signer)
	parsed, err := jwt.ParseWithClaims(access, claims, func(tok *jwt.Token) (any, error) {
		if tok.Method.Alg() != "RS256" {
			t.Fatalf("unexpected alg %s", tok.Method.Alg())
		}
		return pub, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("re-minted token must verify against the signer: %v", err)
	}
	if claims["sub"] != "user-42" || claims["token_use"] != "mcp_session" || claims["authid"] != "auth-1" {
		t.Fatalf("unexpected re-minted claims: %v", claims)
	}
}

func TestRefreshUnknownTokenFallsBackToIdP(t *testing.T) {
	t.Parallel()
	idp, captured := fakeIdP(t)
	proxy := newProxyUnderTest(t, idp.URL, newMemFlowStore())

	token, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "not-a-session",
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if token["access_token"] != "idp-access-token" {
		t.Fatalf("non-session refresh must proxy to the IdP, got %v", token)
	}
	if captured.Get("refresh_token") != "not-a-session" || captured.Get("grant_type") != "refresh_token" {
		t.Fatalf("IdP refresh used wrong form: %v", *captured)
	}
}

func TestRefreshUnknownGatewayTokenRejected(t *testing.T) {
	t.Parallel()
	noIdP := &http.Client{Transport: failingTransport{t}}
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, noIdP, newMemFlowStore(), nil, newTestSigner(t), nil)

	_, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "gwrt_rotated-or-unknown",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("expected invalid_grant for an unknown gateway refresh token, got %v", err)
	}
}

func TestCallbackSessionMintsIdPGrantedScopes(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	idp := fakeIdPWithScopedToken(t, "read:user repo", unsignedJWT(t, map[string]any{"sub": "user-77"}))
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{
			Issuer:         idp.URL,
			ClientID:       "gw-client-id",
			SessionMode:    true,
			RequiredScopes: []string{"api://gw-client-id/mcp.access"},
		}),
	}}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, store, nil, signer, nil)
	ctx := context.Background()

	gwState := authorizeAndGetState(t, proxy, "")
	clientLoc, err := proxy.Callback(ctx, "http://gw.example.com", gwState, "idp-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cu, err := url.Parse(clientLoc)
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	gwCode := cu.Query().Get("code")

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         gwCode,
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp["scope"] != "read:user repo" {
		t.Fatalf("minted scope must reflect the IdP-granted scopes, got %v", resp["scope"])
	}

	access, _ := resp["access_token"].(string)
	claims := jwt.MapClaims{}
	pub := signerPublicKey(t, signer)
	if _, err := jwt.ParseWithClaims(access, claims, func(*jwt.Token) (any, error) { return pub, nil }); err != nil {
		t.Fatalf("minted token must verify: %v", err)
	}
	if claims["scope"] != "read:user repo" {
		t.Fatalf("minted token scope claim must equal the granted scopes, got %v", claims["scope"])
	}
}

// fakeIdPWithScopedToken serves AS metadata and a token endpoint that returns a
// granted scope plus an id_token carrying the subject.
func fakeIdPWithScopedToken(t *testing.T, scope, idToken string) *httptest.Server {
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "idp-access-token",
				"id_token":     idToken,
				"scope":        scope,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeOffModeReturnsTokenVerbatim(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, http.DefaultClient, store, nil, newTestSigner(t), nil)
	ctx := context.Background()

	idpToken := map[string]any{"access_token": "idp-access-token", "token_type": "Bearer", "expires_in": 3600}
	if err := store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Token:         idpToken,
	}); err != nil {
		t.Fatalf("save code: %v", err)
	}

	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp["access_token"] != "idp-access-token" {
		t.Fatalf("OFF mode must return the IdP token verbatim, got %v", resp)
	}
	if _, ok := resp["refresh_token"]; ok {
		t.Fatalf("OFF mode must not add a gateway refresh_token, got %v", resp)
	}
}
