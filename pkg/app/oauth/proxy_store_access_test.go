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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	oidcauth "github.com/NeuralTrust/TrustGate/pkg/infra/auth/oidc"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/golang-jwt/jwt/v5"
)

func TestStoreAccessFromToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token map[string]any
		want  string
	}{
		{
			name:  "store_access in access token",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"sub": "u1", "store_access": "curated"})},
			want:  "curated",
		},
		{
			name: "id_token wins over access token",
			token: map[string]any{
				"id_token":     unsignedJWT(t, map[string]any{"store_access": "none"}),
				"access_token": unsignedJWT(t, map[string]any{"store_access": "open"}),
			},
			want: "none",
		},
		{
			name:  "blank is ignored",
			token: map[string]any{"access_token": unsignedJWT(t, map[string]any{"store_access": "  "})},
			want:  "",
		},
		{
			name:  "opaque token has none",
			token: map[string]any{"access_token": "gho_opaque"},
			want:  "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := storeAccessFromToken(tt.token); got != tt.want {
				t.Fatalf("storeAccessFromToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The control plane mints store_access into the platform token to say which
// slice of the MCP Store this user may see. The gateway session must carry it:
// dropping it makes every default-IdP user fall back to the gateway-wide Store
// mode, so a user the admin restricted to "none" or "curated" browses the whole
// catalog.
func TestExchangeCodeSessionModeCarriesStoreAccess(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil)
	ctx := context.Background()

	if err := store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        "auth-1",
		GatewayID:     "gw-1",
		StoreAccess:   "curated",
		Scopes:        []string{"mcp.access"},
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

	claims := mintedSessionClaims(t, signer, resp)
	if claims[identity.ClaimStoreAccess] != "curated" {
		t.Fatalf("session token must carry store_access, got %v", claims[identity.ClaimStoreAccess])
	}
	rec := store.peekSession(resp["refresh_token"].(string))
	if rec == nil {
		t.Fatal("session record must be persisted")
		return
	}
	if rec.StoreAccess != "curated" {
		t.Fatalf("session record must carry store_access, got %+v", rec)
	}
}

func TestExchangeCodeSessionModeOmitsStoreAccessWhenAbsent(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil)
	ctx := context.Background()

	if err := store.SaveCode(ctx, "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        "auth-1",
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
	if _, present := mintedSessionClaims(t, signer, resp)[identity.ClaimStoreAccess]; present {
		t.Fatal("an absent store_access must stay absent so the gateway default applies")
	}
}

func TestRefreshSessionPreservesStoreAccess(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil)
	ctx := context.Background()

	const oldRefresh = "gwrt_old"
	if err := store.SaveSession(ctx, oldRefresh, SessionRecord{
		Subject:     "user-42",
		Scopes:      []string{"mcp.access"},
		GatewayID:   "gw-1",
		AuthID:      "auth-1",
		StoreAccess: "none",
		LoginAt:     time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
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
	if got := mintedSessionClaims(t, signer, resp)[identity.ClaimStoreAccess]; got != "none" {
		t.Fatalf("refreshed token must re-stamp store_access, got %v", got)
	}
	rotated := store.peekSession(resp["refresh_token"].(string))
	if rotated == nil || rotated.StoreAccess != "none" {
		t.Fatalf("rotated record must preserve store_access, got %+v", rotated)
	}
}

// --- platform token verification -------------------------------------------

// platformIdP is a fake NeuralTrust platform: an authorization server whose
// token endpoint returns the given access token and whose JWKS is the given
// document. The issuer is whatever the caller stamps into the token.
func platformIdP(t *testing.T, accessToken string, jwks map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": accessToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// defaultIdPFixture wires the built-in default IdP against a fake platform and
// resolves the MCP Store resource to it, mirroring how a real login reaches the
// callback with a platform token.
type defaultIdPFixture struct {
	proxy AuthProxy
	store *memFlowStore
	ctx   context.Context
}

func newDefaultIdPFixture(t *testing.T, idp *httptest.Server, issuer string, audience string, opts ...ProxyOption) *defaultIdPFixture {
	t.Helper()
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer:       issuer,
		AuthorizeURL: idp.URL + "/authorize",
		TokenURL:     idp.URL + "/token",
		JWKSURL:      idp.URL + "/jwks",
		ClientID:     "trustgate",
		Audiences:    []string{audience},
	})
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/store/mcp": {{GatewayID: ids.GatewayID{}}},
	}}
	store := newMemFlowStore()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, store, nil, newTestSigner(t), nil, opts...)
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	return &defaultIdPFixture{
		proxy: proxy,
		store: store,
		ctx:   appgateway.WithGateway(context.Background(), gw),
	}
}

// login runs authorize + callback and returns the callback outcome.
func (f *defaultIdPFixture) login(t *testing.T) (string, error) {
	t.Helper()
	loc, err := f.proxy.Authorize(f.ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "trustgate",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/store/mcp",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	return f.proxy.Callback(f.ctx, "http://gw.example.com", u.Query().Get("state"), "platform-code", "", "", "")
}

// platformToken mints an RS256 token the way the platform would, using an STS
// signer as the platform's key pair.
func platformToken(t *testing.T, platform *infrasts.Signer, claims map[string]any) string {
	t.Helper()
	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	signed, err := platform.MintClaims(mc, time.Hour)
	if err != nil {
		t.Fatalf("mint platform token: %v", err)
	}
	return signed
}

func TestCallbackDefaultIdPVerifiesPlatformTokenAndCarriesClaims(t *testing.T) {
	t.Parallel()
	platform := newTestSigner(t) // issuer https://gw.example.com/sts
	token := platformToken(t, platform, map[string]any{
		"sub":          "platform-user-1",
		"aud":          "neuraltrust-mcp",
		"email":        "ada@neuraltrust.ai",
		"org":          "team-a",
		"groups":       []string{"Eng"},
		"store_access": "curated",
	})
	idp := platformIdP(t, token, platform.JWKS())
	fx := newDefaultIdPFixture(t, idp, platform.Issuer(), "neuraltrust-mcp",
		WithIdPTokenVerifier(oidcauth.NewVerifier()))

	loc, err := fx.login(t)
	if err != nil {
		t.Fatalf("callback with a valid platform token must succeed: %v", err)
	}
	if loc == "" {
		t.Fatal("expected a client redirect")
	}
	grant := fx.store.peekFirstGrant()
	if grant == nil {
		t.Fatal("callback must park a code grant")
		return
	}
	if grant.Subject != "platform-user-1" || grant.Email != "ada@neuraltrust.ai" || grant.Org != "team-a" {
		t.Fatalf("verified claims must feed the grant, got %+v", grant)
	}
	if grant.StoreAccess != "curated" {
		t.Fatalf("store_access must survive the callback, got %q", grant.StoreAccess)
	}
	if len(grant.Groups) != 1 || grant.Groups[0] != "Eng" {
		t.Fatalf("groups must survive the callback, got %v", grant.Groups)
	}
}

func TestCallbackDefaultIdPRejectsForgedPlatformToken(t *testing.T) {
	t.Parallel()
	platform := newTestSigner(t)
	attacker := newTestSigner(t) // same issuer string, different key
	forged := platformToken(t, attacker, map[string]any{
		"sub":          "victim",
		"aud":          "neuraltrust-mcp",
		"org":          "team-a",
		"store_access": "open",
	})
	idp := platformIdP(t, forged, platform.JWKS())
	fx := newDefaultIdPFixture(t, idp, platform.Issuer(), "neuraltrust-mcp",
		WithIdPTokenVerifier(oidcauth.NewVerifier()))

	_, err := fx.login(t)
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("a token not signed by the platform key must be refused with access_denied, got %v", err)
	}
	if fx.store.peekFirstGrant() != nil {
		t.Fatal("no code grant may be parked for an unverified token")
	}
}

func TestCallbackDefaultIdPRejectsWrongAudienceAndUnsignedToken(t *testing.T) {
	t.Parallel()
	platform := newTestSigner(t)

	t.Run("wrong audience", func(t *testing.T) {
		t.Parallel()
		token := platformToken(t, platform, map[string]any{"sub": "u1", "aud": "some-other-api"})
		idp := platformIdP(t, token, platform.JWKS())
		fx := newDefaultIdPFixture(t, idp, platform.Issuer(), "neuraltrust-mcp",
			WithIdPTokenVerifier(oidcauth.NewVerifier()))
		_, err := fx.login(t)
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != "access_denied" {
			t.Fatalf("expected access_denied for an audience mismatch, got %v", err)
		}
	})

	t.Run("unsigned token", func(t *testing.T) {
		t.Parallel()
		token := unsignedJWT(t, map[string]any{"sub": "u1", "aud": "neuraltrust-mcp", "iss": platform.Issuer(), "store_access": "open"})
		idp := platformIdP(t, token, platform.JWKS())
		fx := newDefaultIdPFixture(t, idp, platform.Issuer(), "neuraltrust-mcp",
			WithIdPTokenVerifier(oidcauth.NewVerifier()))
		_, err := fx.login(t)
		var oe *OAuthError
		if !errors.As(err, &oe) || oe.Code != "access_denied" {
			t.Fatalf("expected access_denied for an unsigned token, got %v", err)
		}
		if fx.store.peekFirstGrant() != nil {
			t.Fatal("no code grant may be parked for an unsigned token")
		}
	})
}

// Without a verifier the proxy keeps its previous behaviour and reads the
// platform claims unverified (a warning is logged once).
func TestCallbackDefaultIdPWithoutVerifierTrustsClaims(t *testing.T) {
	t.Parallel()
	token := unsignedJWT(t, map[string]any{
		"sub":          "platform-user-1",
		"org":          "team-a",
		"store_access": "none",
	})
	idp := platformIdP(t, token, map[string]any{"keys": []any{}})
	fx := newDefaultIdPFixture(t, idp, "https://app.example.com/api/mcp/oauth", "neuraltrust-mcp")

	if _, err := fx.login(t); err != nil {
		t.Fatalf("callback without a verifier must keep working: %v", err)
	}
	grant := fx.store.peekFirstGrant()
	if grant == nil || grant.Subject != "platform-user-1" || grant.Org != "team-a" || grant.StoreAccess != "none" {
		t.Fatalf("unverified claims must still feed the grant, got %+v", grant)
	}
}

// Operator-configured identity providers are untouched by the verifier: their
// tokens are often opaque or minted for another audience.
func TestCallbackOperatorIdPIgnoresVerifier(t *testing.T) {
	t.Parallel()
	idp := fakeIdPWithToken(t, unsignedJWT(t, map[string]any{"sub": "user-77"}))
	store := newMemFlowStore()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{
		oauth2Auth(t, authdomain.OAuth2Config{Issuer: idp.URL, ClientID: "gw-client-id", SessionMode: true}),
	}}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, store, nil, newTestSigner(t), nil,
		WithIdPTokenVerifier(oidcauth.NewVerifier()))

	gwState := authorizeAndGetState(t, proxy, "")
	if _, err := proxy.Callback(context.Background(), "http://gw.example.com", gwState, "idp-code", "", "", ""); err != nil {
		t.Fatalf("operator IdP callback must not be subject to platform verification: %v", err)
	}
}

// --- session lifetime -------------------------------------------------------

func fixedClock(at time.Time) func() time.Time { return func() time.Time { return at } }

func TestExchangeCodeStampsAbsoluteSessionDeadline(t *testing.T) {
	t.Parallel()
	loginAt := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		authID   string
		opts     []ProxyOption
		lifetime time.Duration
	}{
		{"default idp uses configured max age", appauth.DefaultIdPAuthID().String(), []ProxyOption{WithDefaultIdPSessionMaxAge(8 * time.Hour)}, 8 * time.Hour},
		{"default idp falls back to 24h", appauth.DefaultIdPAuthID().String(), nil, DefaultIdPSessionMaxAge},
		{"operator idp keeps 30d", "auth-1", nil, operatorSessionLifetime},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newMemFlowStore()
			proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, newTestSigner(t), nil, tc.opts...).(*authProxy)
			proxy.now = fixedClock(loginAt)
			ctx := context.Background()
			if err := store.SaveCode(ctx, "gw-code", CodeGrant{
				RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
				CodeChallenge: s256("client-verifier"),
				Subject:       "user-42",
				AuthID:        tc.authID,
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
			rec := store.peekSession(resp["refresh_token"].(string))
			if rec == nil {
				t.Fatal("session record must be persisted")
				return
			}
			if !rec.LoginAt.Equal(loginAt) {
				t.Fatalf("LoginAt = %v, want %v", rec.LoginAt, loginAt)
			}
			if want := loginAt.Add(tc.lifetime); !rec.ExpiresAt.Equal(want) {
				t.Fatalf("ExpiresAt = %v, want %v", rec.ExpiresAt, want)
			}
		})
	}
}

func seedDefaultIdPSession(t *testing.T, store *memFlowStore, refresh string, loginAt time.Time, lifetime time.Duration) {
	t.Helper()
	if err := store.SaveSession(context.Background(), refresh, SessionRecord{
		Subject:     "user-42",
		Scopes:      []string{"mcp.access"},
		GatewayID:   "gw-1",
		AuthID:      appauth.DefaultIdPAuthID().String(),
		Org:         "team-a",
		StoreAccess: "curated",
		LoginAt:     loginAt,
		ExpiresAt:   loginAt.Add(lifetime),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func TestRefreshSessionWithinWindowKeepsDeadline(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	noIdP := &http.Client{Transport: failingTransport{t}}
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, noIdP, store, nil, newTestSigner(t), nil).(*authProxy)
	loginAt := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	seedDefaultIdPSession(t, store, "gwrt_old", loginAt, 24*time.Hour)

	proxy.now = fixedClock(loginAt.Add(23 * time.Hour))
	resp, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "gwrt_old",
	})
	if err != nil {
		t.Fatalf("refresh inside the window must succeed: %v", err)
	}
	rotated := store.peekSession(resp["refresh_token"].(string))
	if rotated == nil {
		t.Fatal("rotated session must be persisted")
		return
	}
	// Rotation renews the token, never the session: the deadline is the one
	// fixed at login, not 24h from this refresh.
	if !rotated.LoginAt.Equal(loginAt) || !rotated.ExpiresAt.Equal(loginAt.Add(24*time.Hour)) {
		t.Fatalf("rotation must not slide the session deadline, got login=%v expires=%v", rotated.LoginAt, rotated.ExpiresAt)
	}
	if rotated.StoreAccess != "curated" || rotated.Org != "team-a" {
		t.Fatalf("rotation must preserve claims, got %+v", rotated)
	}
}

func TestRefreshSessionPastWindowRefused(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	noIdP := &http.Client{Transport: failingTransport{t}}
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, noIdP, store, nil, newTestSigner(t), nil).(*authProxy)
	loginAt := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	seedDefaultIdPSession(t, store, "gwrt_old", loginAt, 24*time.Hour)

	proxy.now = fixedClock(loginAt.Add(24*time.Hour + time.Second))
	_, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "gwrt_old",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("refresh past the absolute deadline must be invalid_grant so the client re-authorizes, got %v", err)
	}
	if len(store.sessions) != 1 {
		t.Fatalf("a refused refresh must not mint a new session, got %d records", len(store.sessions))
	}
}

// Records written before the deadline existed cannot prove they are still
// inside one; they are refused so the client re-authorizes once.
func TestRefreshSessionWithoutDeadlineRefused(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, newTestSigner(t), nil)
	if err := store.SaveSession(context.Background(), "gwrt_legacy", SessionRecord{
		Subject: "user-42", AuthID: "auth-1", GatewayID: "gw-1",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "gwrt_legacy",
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("expected invalid_grant for a record without a deadline, got %v", err)
	}
}

// TestCallbackRefusesTokenMintedForAnotherGateway: Access policies are
// gateway-scoped, so a platform token whose gateway claim names another gateway
// of the tenant (a user edited the hint mid-login to borrow a laxer policy) is
// refused; one naming this gateway, or none, is accepted.
func TestCallbackRefusesTokenMintedForAnotherGateway(t *testing.T) {
	t.Parallel()
	platform := newTestSigner(t)
	foreign := platformToken(t, platform, map[string]any{
		"sub": "platform-user-1", "aud": "neuraltrust-mcp", "org": "team-a",
		"gateway": ids.New[ids.GatewayKind]().String(), "store_access": "open",
	})
	fx := newDefaultIdPFixture(t, platformIdP(t, foreign, platform.JWKS()), platform.Issuer(), "neuraltrust-mcp",
		WithIdPTokenVerifier(oidcauth.NewVerifier()))
	if _, err := fx.login(t); err == nil {
		t.Fatal("a token minted for another gateway must be refused")
	}
	if fx.store.peekFirstGrant() != nil {
		t.Fatal("no code grant may be parked for a refused token")
	}

	own := newDefaultIdPFixtureGateway(t, platform, "neuraltrust-mcp")
	if _, err := own.login(t); err != nil {
		t.Fatalf("a token minted for this gateway must be accepted: %v", err)
	}
}

// newDefaultIdPFixtureGateway builds a fixture whose platform token names the
// fixture's own gateway (the token has to be minted after the gateway id exists).
func newDefaultIdPFixtureGateway(t *testing.T, platform *infrasts.Signer, audience string) *defaultIdPFixture {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	token := platformToken(t, platform, map[string]any{
		"sub": "platform-user-1", "aud": audience, "org": "team-a",
		"gateway": gw.ID.String(), "store_access": "curated",
	})
	idp := platformIdP(t, token, platform.JWKS())
	fx := newDefaultIdPFixture(t, idp, platform.Issuer(), audience, WithIdPTokenVerifier(oidcauth.NewVerifier()))
	fx.ctx = appgateway.WithGateway(context.Background(), gw)
	return fx
}
