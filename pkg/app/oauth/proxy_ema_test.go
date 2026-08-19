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
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/golang-jwt/jwt/v5"
)

func setupEMAProxy(t *testing.T, mode string, stub appauth.OIDCVerifier, store *memFlowStore) (AuthProxy, *memFlowStore, *authdomain.Auth) {
	t.Helper()
	auth := enabledOAuth2Auth(t, authdomain.OAuth2Config{
		Issuer:         "https://idp.example.com",
		JWKSURL:        "https://idp.example.com/jwks",
		NorthboundMode: mode,
		Audiences:      []string{"api://gw"},
		RequiredScopes: []string{"mcp.access"},
		ClientID:       "gw-client-id",
	})
	if store == nil {
		store = newMemFlowStore()
	}
	if err := store.SaveGatewayClient(context.Background(), RegisteredGatewayClient{
		ClientID:     "agw-client",
		RedirectURIs: []string{"https://127.0.0.1/cb"},
	}); err != nil {
		t.Fatalf("save client: %v", err)
	}
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{auth}}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, store, nil, newTestSigner(t), nil, stub)
	return proxy, store, auth
}

func validBearerReq(t *testing.T, stub *stubOIDCVerifier) TokenRequest {
	t.Helper()
	now := time.Now()
	claims := validJAGClaims(now, nil)
	stub.hints = appauth.TokenHints{Issuer: "https://idp.example.com", Algorithm: "RS256"}
	stub.verified = &appauth.VerifiedClaims{Subject: "user-1", Claims: claims, Scopes: []string{"mcp.access"}}
	return TokenRequest{
		GrantType: grantJWTBearer,
		Assertion: jagJWT(idJAGTyp, "RS256"),
		ClientID:  "agw-client",
		Resource:  "https://gw.example.com/v1/mcp/dev",
	}
}

func parseSessionClaims(t *testing.T, accessToken string) jwt.MapClaims {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse session: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected map claims")
	}
	return claims
}

func TestOIDCRejectsJWTBearer(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"", authdomain.NorthboundModeOIDC} {
		t.Run("mode_"+mode, func(t *testing.T) {
			t.Parallel()
			proxy, _, _ := setupEMAProxy(t, mode, &stubOIDCVerifier{}, nil)
			_, err := proxy.Exchange(context.Background(), "https://gw.example.com", TokenRequest{
				GrantType: grantJWTBearer,
				Assertion: jagJWT(idJAGTyp, "RS256"),
				ClientID:  "agw-client",
				Resource:  "https://gw.example.com/v1/mcp/dev",
			})
			var oe *OAuthError
			if !errors.As(err, &oe) || oe.Code != "unsupported_grant_type" {
				t.Fatalf("got %v, want unsupported_grant_type", err)
			}
		})
	}
}

func TestBothJWTBearerNoOIDCDowngrade(t *testing.T) {
	t.Parallel()
	stub := &stubOIDCVerifier{
		hints: appauth.TokenHints{Issuer: "https://idp.example.com", Algorithm: "RS256"},
	}
	proxy, _, _ := setupEMAProxy(t, authdomain.NorthboundModeBoth, stub, nil)
	_, err := proxy.Exchange(context.Background(), "https://gw.example.com", TokenRequest{
		GrantType: grantJWTBearer,
		Assertion: jagJWT("JWT", "RS256"),
		ClientID:  "agw-client",
		Resource:  "https://gw.example.com/v1/mcp/dev",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("got %v, want invalid_grant with no OIDC fallback", err)
	}
}

func TestEMARejectsAuthorizeKeepsRefresh(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	proxy, _, auth := setupEMAProxy(t, authdomain.NorthboundModeEMA, &stubOIDCVerifier{}, store)
	location, err := proxy.Authorize(context.Background(), "https://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "agw-client",
		RedirectURI:         "https://127.0.0.1/cb",
		CodeChallenge:       s256("verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize refusal should reach the client: %v", err)
	}
	assertClientToldOfError(t, location, "https://127.0.0.1/cb", "https://gw.example.com", "access_denied")

	refresh := gatewayRefreshPrefix + "keep"
	if err := store.SaveSession(context.Background(), refresh, SessionRecord{
		Subject:   "user-1",
		Scopes:    []string{"mcp.access"},
		GatewayID: auth.GatewayID.String(),
		AuthID:    auth.ID.String(),
		Audiences: []string{"api://gw"},
	}); err != nil {
		t.Fatalf("save session: %v", err)
	}
	resp, err := proxy.Exchange(context.Background(), "https://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refresh,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if resp["access_token"] == nil {
		t.Fatal("expected a minted session on refresh")
	}
}

func TestJWTBearerMintsSessionNotIDJAG(t *testing.T) {
	t.Parallel()
	stub := &stubOIDCVerifier{}
	proxy, store, auth := setupEMAProxy(t, authdomain.NorthboundModeBoth, stub, nil)
	req := validBearerReq(t, stub)
	req.Assertion = jagJWT(idJAGTyp, "RS256")
	resp, err := proxy.Exchange(context.Background(), "https://gw.example.com", req)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	access, _ := resp["access_token"].(string)
	if access == "" || access == req.Assertion {
		t.Fatal("must mint a session JWT, not return the ID-JAG")
	}
	claims := parseSessionClaims(t, access)
	if claims["token_use"] != "mcp_session" {
		t.Fatalf("token_use = %v", claims["token_use"])
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v, want iss+sub identity not email", claims["sub"])
	}
	if claims["sub"] == "nobody@example.com" {
		t.Fatal("email must not become the subject")
	}
	if claims["authid"] != auth.ID.String() {
		t.Fatalf("authid = %v", claims["authid"])
	}
	if claims["gwid"] != auth.GatewayID.String() {
		t.Fatalf("gwid = %v", claims["gwid"])
	}
	refresh, _ := resp["refresh_token"].(string)
	if !strings.HasPrefix(refresh, gatewayRefreshPrefix) {
		t.Fatalf("refresh = %q", refresh)
	}
	if rec := store.peekSession(refresh); rec == nil {
		t.Fatal("expected persisted session")
	}
}

func TestJWTBearerEmailLinkingOnlyAndActDropped(t *testing.T) {
	t.Parallel()
	now := time.Now()
	claims := validJAGClaims(now, map[string]any{
		"email": "unmatched@example.com",
		"act":   map[string]any{"sub": "delegate"},
	})
	stub := &stubOIDCVerifier{
		hints:    appauth.TokenHints{Issuer: "https://idp.example.com", Algorithm: "RS256"},
		verified: &appauth.VerifiedClaims{Subject: "user-1", Claims: claims, Scopes: []string{"mcp.access"}},
	}
	proxy, _, _ := setupEMAProxy(t, authdomain.NorthboundModeEMA, stub, nil)
	resp, err := proxy.Exchange(context.Background(), "https://gw.example.com", TokenRequest{
		GrantType: grantJWTBearer,
		Assertion: jagJWT(idJAGTyp, "RS256"),
		ClientID:  "agw-client",
		Resource:  "https://gw.example.com/v1/mcp/dev",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	session := parseSessionClaims(t, resp["access_token"].(string))
	if session["sub"] != "user-1" {
		t.Fatalf("sub = %v", session["sub"])
	}
	if session["sub"] == "unmatched@example.com" {
		t.Fatal("email must not replace subject")
	}
	if _, ok := session["act"]; ok {
		t.Fatal("act must not be copied into the session")
	}
	if session["jti"] == "jti-1" {
		t.Fatal("assertion jti must not be copied into the session")
	}
}

func TestJWTBearerJTIReplayAndStoreDown(t *testing.T) {
	t.Parallel()
	stub := &stubOIDCVerifier{}
	store := newMemFlowStore()
	proxy, _, _ := setupEMAProxy(t, authdomain.NorthboundModeBoth, stub, store)
	req := validBearerReq(t, stub)
	if _, err := proxy.Exchange(context.Background(), "https://gw.example.com", req); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	_, err := proxy.Exchange(context.Background(), "https://gw.example.com", req)
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("replay = %v, want invalid_grant", err)
	}

	store.jtis = map[string]struct{}{}
	store.jtiErr = errors.New("redis down")
	_, err = proxy.Exchange(context.Background(), "https://gw.example.com", TokenRequest{
		GrantType: grantJWTBearer,
		Assertion: jagJWT(idJAGTyp, "RS256"),
		ClientID:  "agw-client",
		Resource:  "https://gw.example.com/v1/mcp/dev",
	})
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("store down = %v, want invalid_grant", err)
	}
}
