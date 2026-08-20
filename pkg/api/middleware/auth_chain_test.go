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
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authrepomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	authsession "github.com/NeuralTrust/TrustGate/pkg/infra/auth/session"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeAPIKeyFinder struct {
	auth *authdomain.Auth
	err  error
}

func (f fakeAPIKeyFinder) FindByAPIKey(_ context.Context, _ string) (*authdomain.Auth, error) {
	return f.auth, f.err
}

type fakeCredentialFinder struct {
	oauth2     []*authdomain.Auth
	mtls       []*authdomain.Auth
	defaultIdP *authdomain.Auth
}

func (f fakeCredentialFinder) DefaultOAuth2ForGateway(gatewayID ids.GatewayID) *authdomain.Auth {
	if f.defaultIdP == nil {
		return nil
	}
	clone := *f.defaultIdP
	clone.GatewayID = gatewayID
	return &clone
}

func (f fakeCredentialFinder) OAuth2Auths(context.Context) ([]*authdomain.Auth, error) {
	return f.oauth2, nil
}

func (f fakeCredentialFinder) OAuth2AuthsForGateway(_ context.Context, gatewayID ids.GatewayID) ([]*authdomain.Auth, error) {
	out := make([]*authdomain.Auth, 0, len(f.oauth2))
	for _, a := range f.oauth2 {
		if a.GatewayID == gatewayID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f fakeCredentialFinder) MTLSAuths(context.Context) ([]*authdomain.Auth, error) {
	return f.mtls, nil
}

type fakeTokenValidator struct {
	principal *identity.Principal
	err       error
	calls     int
}

func (f *fakeTokenValidator) Validate(_ context.Context, _ string, _ *authdomain.OAuth2Config) (*identity.Principal, error) {
	f.calls++
	return f.principal, f.err
}

type fakeMTLSValidator struct {
	principal *identity.Principal
	err       error
}

func (f *fakeMTLSValidator) Validate(_ *x509.Certificate, _ *authdomain.MTLSConfig) (*identity.Principal, error) {
	return f.principal, f.err
}

func oauth2Auth(t *testing.T, issuer string, jwks bool) *authdomain.Auth {
	t.Helper()
	cfg := &authdomain.OAuth2Config{Issuer: issuer, Audiences: []string{"trustgate"}}
	if jwks {
		cfg.JWKSURL = "https://idp.example.com/jwks"
	} else {
		cfg.IntrospectionURL = "https://idp.example.com/introspect"
	}
	a, err := authdomain.NewAuth(ids.New[ids.GatewayKind](), "idp", authdomain.TypeOAuth2, true, authdomain.Config{OAuth2: cfg})
	require.NoError(t, err)
	return a
}

func brokerCapableOAuth2Auth(t *testing.T, issuer string) *authdomain.Auth {
	t.Helper()
	a := oauth2Auth(t, issuer, true)
	a.Config.OAuth2.ClientID = "trustgate-client"
	a.Config.OAuth2.AuthorizeURL = issuer + "/authorize"
	a.Config.OAuth2.TokenURL = issuer + "/token"
	return a
}

func legacyOIDCAuth(t *testing.T, issuer string) *authdomain.Auth {
	t.Helper()
	payload := fmt.Sprintf(`{"oidc":{"issuer":%q,"audiences":["trustgate"],"jwks_url":%q}}`, issuer, issuer+"/jwks")
	var cfg authdomain.Config
	require.NoError(t, json.Unmarshal([]byte(payload), &cfg))
	require.Nil(t, cfg.OIDC, "the legacy payload must decode onto the oauth2 shape")
	a, err := authdomain.NewAuth(
		ids.New[ids.GatewayKind](), "legacy-idp", authdomain.NormalizeType(authdomain.TypeOIDC), true, cfg,
	)
	require.NoError(t, err)
	return a
}

func unsignedJWT(t *testing.T, issuer string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": issuer,
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := token.SignedString([]byte("test-only"))
	require.NoError(t, err)
	return raw
}

func resolveChain(
	t *testing.T,
	resolver middleware.IdentityResolver,
	headers map[string]string,
) (middleware.Identity, error) {
	t.Helper()
	var (
		gotIdentity middleware.Identity
		gotErr      error
	)
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		gotIdentity, gotErr = resolver.Resolve(c)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	_, err := app.Test(req)
	require.NoError(t, err)
	return gotIdentity, gotErr
}

func TestChain_JWTBearer_MatchesIssuerCandidate(t *testing.T) {
	a := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
	intro := &fakeTokenValidator{err: errors.New("must not be called")}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil, jwtVal, intro, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.NoError(t, err)
	require.Equal(t, a.GatewayID, id.GatewayID)
	require.Equal(t, a.ID, id.AuthID)
	require.NotNil(t, id.Principal)
	require.Equal(t, identity.MethodJWT, id.Principal.Method)
	require.Equal(t, 1, jwtVal.calls)
	require.Equal(t, 0, intro.calls)
}

func TestChain_JWTBearer_NoIssuerMatch_Unauthenticated(t *testing.T) {
	a := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1"}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil, jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://other-idp.example.com"),
	})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
	require.Equal(t, 0, jwtVal.calls)
}

func TestChain_OpaqueBearer_GoesToIntrospection(t *testing.T) {
	a := oauth2Auth(t, "https://idp.example.com", false)
	intro := &fakeTokenValidator{principal: &identity.Principal{Subject: "svc", Method: identity.MethodIntrospection}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil, &fakeTokenValidator{}, intro, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer opaque-reference-token"})
	require.NoError(t, err)
	require.Equal(t, identity.MethodIntrospection, id.Principal.Method)
	require.Equal(t, 1, intro.calls)
}

func TestChain_AntiDowngrade_InvalidBearerDoesNotFallThroughToAPIKey(t *testing.T) {
	a := oauth2Auth(t, "https://idp.example.com", true)
	apiKeyAuth, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "key", true)
	require.NoError(t, err)
	jwtVal := &fakeTokenValidator{err: errors.New("bad signature")}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{auth: apiKeyAuth}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil, jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err = resolveChain(t, resolver, map[string]string{
		"Authorization":          "Bearer " + unsignedJWT(t, "https://idp.example.com"),
		apiresolver.HeaderAPIKey: apiKeyAuth.RawKey,
	})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
	require.Equal(t, 1, jwtVal.calls)
}

func TestChain_APIKeyFallback_BuildsPrincipal(t *testing.T) {
	apiKeyAuth, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "partner-key", true)
	require.NoError(t, err)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{auth: apiKeyAuth}, fakeCredentialFinder{}, nil, &fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{apiresolver.HeaderAPIKey: apiKeyAuth.RawKey})
	require.NoError(t, err)
	require.Equal(t, apiKeyAuth.GatewayID, id.GatewayID)
	require.NotNil(t, id.Principal)
	require.Equal(t, identity.MethodAPIKey, id.Principal.Method)
	require.Equal(t, "partner-key", id.Principal.Subject)
}

func TestChain_NoCredential_Unauthenticated(t *testing.T) {
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{}, nil, &fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err := resolveChain(t, resolver, nil)
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

type fakePathResolver struct {
	matches []appconsumer.PathMatch
	err     error
}

func (f fakePathResolver) Match(context.Context, string, string) ([]appconsumer.PathMatch, error) {
	return f.matches, f.err
}

func pathMatchWith(auths ...*authdomain.Auth) appconsumer.PathMatch {
	m := appconsumer.PathMatch{}
	if len(auths) > 0 {
		m.GatewayID = auths[0].GatewayID
	}
	m.Auths = auths
	return m
}

func resolveChallengeMode(
	t *testing.T,
	resolver middleware.IdentityResolver,
) (any, error) {
	t.Helper()

	var (
		mode       any
		resolveErr error
	)
	app := fiber.New()
	app.Post("/runtime/mcp", func(c *fiber.Ctx) error {
		_, resolveErr = resolver.Resolve(c)
		mode = c.Locals(middleware.OAuthChallengeModeLocal)
		return c.SendStatus(fiber.StatusOK)
	})
	_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/runtime/mcp", nil))
	require.NoError(t, err)
	return mode, resolveErr
}

func TestChain_PathFirst_SetsChallengeMode(t *testing.T) {
	t.Parallel()

	brokerCapable := brokerCapableOAuth2Auth(t, "https://idp.example.com")
	validateOnly := oauth2Auth(t, "https://idp.example.com", true)
	legacyOIDC := legacyOIDCAuth(t, "https://legacy-idp.example.com")
	disabledOAuth := oauth2Auth(t, "https://disabled.example.com", true)
	disabledOAuth.Enabled = false
	disabledOIDC := legacyOIDCAuth(t, "https://disabled-legacy.example.com")
	disabledOIDC.Enabled = false
	apiKey, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "key", true)
	require.NoError(t, err)
	disabledAPIKey, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "disabled-key", false)
	require.NoError(t, err)
	lookupErr := errors.New("lookup failed")
	tests := []struct {
		name       string
		paths      appconsumer.PathResolver
		defaultIdP bool
		want       any
	}{
		{
			name:  "broker-capable OAuth2 advertises",
			paths: fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(brokerCapable)}},
			want:  middleware.OAuthChallengeAdvertise,
		},
		{
			name:  "validate-only OAuth2 emits the diagnostic",
			paths: fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(validateOnly)}},
			want:  middleware.OAuthChallengeDiagnostic,
		},
		{
			name:       "validate-only OAuth2 still blocks the default IdP",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(validateOnly)}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeDiagnostic,
		},
		{
			name:  "legacy oidc emits the diagnostic",
			paths: fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(legacyOIDC)}},
			want:  middleware.OAuthChallengeDiagnostic,
		},
		{
			name:       "legacy oidc still blocks the default IdP",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(legacyOIDC)}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeDiagnostic,
		},
		{
			name:  "broker-capable wins over a validate-only sibling",
			paths: fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(validateOnly, brokerCapable)}},
			want:  middleware.OAuthChallengeAdvertise,
		},
		{
			name:       "usable default IdP",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith()}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeAdvertise,
		},
		{
			name:  "API key only",
			paths: fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(apiKey)}},
			want:  middleware.OAuthChallengeSilent,
		},
		{
			name:       "API key blocks default IdP",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(apiKey)}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeSilent,
		},
		{
			name:       "disabled API key does not block default IdP",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(disabledAPIKey)}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeAdvertise,
		},
		{
			name:       "disabled OAuth2 blocks default IdP",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(disabledOAuth)}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeSilent,
		},
		{
			name:       "disabled legacy oidc blocks default IdP like a disabled oauth2",
			paths:      fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(disabledOIDC)}},
			defaultIdP: true,
			want:       middleware.OAuthChallengeSilent,
		},
		{name: "unknown path", paths: fakePathResolver{}},
		{name: "lookup failure", paths: fakePathResolver{err: lookupErr}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver := middleware.NewChainIdentityResolver(
				fakeAPIKeyFinder{},
				fakeCredentialFinder{},
				tt.paths,
				&fakeTokenValidator{},
				&fakeTokenValidator{},
				&fakeMTLSValidator{},
				nil,
				nil,
				nil,
				tt.defaultIdP,
			)
			got, resolveErr := resolveChallengeMode(t, resolver)
			require.ErrorIs(t, resolveErr, apiresolver.ErrUnauthenticated)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestChain_PathFirst_SameIssuerPicksAttachedAuth(t *testing.T) {
	authA := oauth2Auth(t, "https://idp.example.com", true)
	authB := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(authB)}},
		jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.NoError(t, err)
	require.Equal(t, authB.ID, id.AuthID)
	require.Equal(t, authB.GatewayID, id.GatewayID)
	require.Equal(t, 1, jwtVal.calls, "only the attached candidate must be tried")
}

func TestChain_PathFirst_UnattachedCredentialRejected(t *testing.T) {
	authA := oauth2Auth(t, "https://idp.example.com", true)
	otherConsumerAuth := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1"}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{authA}},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(otherConsumerAuth)}},
		jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
	require.Equal(t, 0, jwtVal.calls)
}

func TestChain_PathFirst_NoConsumerMatchRejectsJWT(t *testing.T) {
	a := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{a}},
		fakePathResolver{},
		jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

func TestChain_PathFirst_APIKeyMustBeAttached(t *testing.T) {
	apiKeyAuth, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "key", true)
	require.NoError(t, err)
	otherConsumerAuth := oauth2Auth(t, "https://idp.example.com", true)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{auth: apiKeyAuth},
		fakeCredentialFinder{},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(otherConsumerAuth)}},
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err = resolveChain(t, resolver, map[string]string{apiresolver.HeaderAPIKey: apiKeyAuth.RawKey})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

type fakeCertExtractor struct {
	cert  *x509.Certificate
	calls int
}

func (f *fakeCertExtractor) FromXFCC(string) (*x509.Certificate, error) {
	f.calls++
	return f.cert, nil
}

func TestChain_XFCC_IgnoredWithoutTrustedPeerConfig(t *testing.T) {
	mtlsAuth, err := authdomain.NewAuth(ids.New[ids.GatewayKind](), "mtls", authdomain.TypeMTLS, true,
		authdomain.Config{MTLS: &authdomain.MTLSConfig{CACert: "ca"}})
	require.NoError(t, err)
	extractor := &fakeCertExtractor{cert: &x509.Certificate{}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{mtls: []*authdomain.Auth{mtlsAuth}},
		nil, &fakeTokenValidator{},
		&fakeTokenValidator{},
		&fakeMTLSValidator{principal: &identity.Principal{Subject: "spoofed", Method: identity.MethodMTLS}},
		extractor,
		nil,
		nil, false,
	)

	_, err = resolveChain(t, resolver, map[string]string{
		"X-Forwarded-Client-Cert": `Cert="fake"`,
	})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated,
		"XFCC must be ignored unless TRUST_XFCC_FROM allows the peer")
	require.Equal(t, 0, extractor.calls)
}

func TestChain_XFCC_AcceptedFromTrustedPeer(t *testing.T) {
	mtlsAuth, err := authdomain.NewAuth(ids.New[ids.GatewayKind](), "mtls", authdomain.TypeMTLS, true,
		authdomain.Config{MTLS: &authdomain.MTLSConfig{CACert: "ca"}})
	require.NoError(t, err)
	extractor := &fakeCertExtractor{cert: &x509.Certificate{}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{mtls: []*authdomain.Auth{mtlsAuth}},
		nil, &fakeTokenValidator{},
		&fakeTokenValidator{},
		&fakeMTLSValidator{principal: &identity.Principal{Subject: "svc", Method: identity.MethodMTLS}},
		extractor,
		nil,
		[]string{"0.0.0.0/0", "::/0"}, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{
		"X-Forwarded-Client-Cert": `Cert="real"`,
	})
	require.NoError(t, err)
	require.Equal(t, 1, extractor.calls)
	require.Equal(t, identity.MethodMTLS, id.Principal.Method)
}

func TestChain_PathFirst_LookupErrorFailsClosed(t *testing.T) {
	a := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{a}},
		fakePathResolver{err: errors.New("db down")},
		jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	_, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated,
		"a path-scope lookup failure must not degrade to unrestricted auth")
	require.Equal(t, 0, jwtVal.calls)
}

const sessionIssuer = "https://gw.trustgate.local"

func sessionVerifier(t *testing.T) (*authsession.Verifier, *infrasts.Signer) {
	t.Helper()
	signer, err := infrasts.NewSigner(sessionIssuer, "", nil)
	require.NoError(t, err)
	verifier, err := authsession.NewVerifier(signer)
	require.NoError(t, err)
	return verifier, signer
}

func mintSession(t *testing.T, signer *infrasts.Signer, claims jwt.MapClaims) string {
	t.Helper()
	raw, err := signer.MintClaims(claims, time.Hour)
	require.NoError(t, err)
	return raw
}

func TestChain_SessionToken_ResolvesByAuthID(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	a := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{err: errors.New("must not be called")}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil,
		jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "user-123",
		"aud":       a.Config.OAuth2.Audiences,
		"authid":    a.ID.String(),
		"token_use": "mcp_session",
	})

	id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)
	require.Equal(t, a.GatewayID, id.GatewayID)
	require.Equal(t, a.ID, id.AuthID)
	require.NotNil(t, id.Principal)
	require.Equal(t, "user-123", id.Principal.Subject)
	require.Equal(t, identity.MethodJWT, id.Principal.Method)
	require.Equal(t, sessionIssuer, id.Principal.Issuer)
	require.Equal(t, 0, jwtVal.calls)
}

func TestChain_SessionVerifierPresent_OktaJWTStillUsesResolveJWT(t *testing.T) {
	verifier, _ := sessionVerifier(t)
	a := oauth2Auth(t, "https://idp.example.com", true)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
	intro := &fakeTokenValidator{err: errors.New("must not be called")}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil,
		jwtVal, intro, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.NoError(t, err)
	require.Equal(t, a.ID, id.AuthID)
	require.Equal(t, identity.MethodJWT, id.Principal.Method)
	require.Equal(t, 1, jwtVal.calls)
	require.Equal(t, 0, intro.calls)
}

func TestChain_SessionVerifierPresent_OpaqueTokenStillIntrospects(t *testing.T) {
	verifier, _ := sessionVerifier(t)
	a := oauth2Auth(t, "https://idp.example.com", false)
	intro := &fakeTokenValidator{principal: &identity.Principal{Subject: "svc", Method: identity.MethodIntrospection}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil,
		&fakeTokenValidator{}, intro, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer opaque-reference-token"})
	require.NoError(t, err)
	require.Equal(t, identity.MethodIntrospection, id.Principal.Method)
	require.Equal(t, 1, intro.calls)
}

func TestChain_SessionToken_CrossAuthIDOnScopedPathRejected(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	authA := oauth2Auth(t, "https://idp.example.com", true)
	authB := oauth2Auth(t, "https://idp.example.com", true)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(authA)}},
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "user-123",
		"aud":       authB.Config.OAuth2.Audiences,
		"authid":    authB.ID.String(),
		"token_use": "mcp_session",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

func TestChain_SessionToken_WrongTokenUseRejected(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	a := oauth2Auth(t, "https://idp.example.com", true)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil,
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "user-123",
		"aud":       a.Config.OAuth2.Audiences,
		"authid":    a.ID.String(),
		"token_use": "exchange",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

func TestChain_SessionToken_AudienceMismatchRejected(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	a := oauth2Auth(t, "https://idp.example.com", true)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil,
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "user-123",
		"aud":       []string{"some-other-audience"},
		"authid":    a.ID.String(),
		"token_use": "mcp_session",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

func TestChain_SessionToken_EmptySubjectRejected(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	a := oauth2Auth(t, "https://idp.example.com", true)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{a}}, nil,
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, verifier, nil, false,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "",
		"aud":       a.Config.OAuth2.Audiences,
		"authid":    a.ID.String(),
		"token_use": "mcp_session",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

func TestChain_ValidateOnlyAuth_StillAuthenticates(t *testing.T) {
	t.Parallel()

	validateOnly := oauth2Auth(t, "https://idp.example.com", true)
	require.False(t, validateOnly.CanBrokerLogin(), "fixture must be validate-only")

	t.Run("resolveJWT", func(t *testing.T) {
		t.Parallel()
		jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
		resolver := middleware.NewChainIdentityResolver(
			fakeAPIKeyFinder{},
			fakeCredentialFinder{oauth2: []*authdomain.Auth{validateOnly}},
			fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(validateOnly)}},
			jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
		)

		id, err := resolveChain(t, resolver, map[string]string{
			"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
		})
		require.NoError(t, err)
		require.Equal(t, validateOnly.ID, id.AuthID)
		require.Equal(t, 1, jwtVal.calls)
	})

	t.Run("resolveOpaque", func(t *testing.T) {
		t.Parallel()
		opaqueAuth := oauth2Auth(t, "https://idp.example.com", false)
		require.False(t, opaqueAuth.CanBrokerLogin())
		intro := &fakeTokenValidator{principal: &identity.Principal{Subject: "svc", Method: identity.MethodIntrospection}}
		resolver := middleware.NewChainIdentityResolver(
			fakeAPIKeyFinder{},
			fakeCredentialFinder{oauth2: []*authdomain.Auth{opaqueAuth}},
			fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(opaqueAuth)}},
			&fakeTokenValidator{}, intro, &fakeMTLSValidator{}, nil, nil, nil, false,
		)

		id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer opaque-reference-token"})
		require.NoError(t, err)
		require.Equal(t, identity.MethodIntrospection, id.Principal.Method)
		require.Equal(t, 1, intro.calls)
	})

	t.Run("resolveSession", func(t *testing.T) {
		t.Parallel()
		verifier, signer := sessionVerifier(t)
		resolver := middleware.NewChainIdentityResolver(
			fakeAPIKeyFinder{},
			fakeCredentialFinder{oauth2: []*authdomain.Auth{validateOnly}},
			fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(validateOnly)}},
			&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, verifier, nil, false,
		)

		token := mintSession(t, signer, jwt.MapClaims{
			"sub":       "user-123",
			"aud":       validateOnly.Config.OAuth2.Audiences,
			"authid":    validateOnly.ID.String(),
			"token_use": "mcp_session",
		})

		id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
		require.NoError(t, err)
		require.Equal(t, validateOnly.ID, id.AuthID)
	})
}

func TestChain_LegacyOIDCAuth_AuthenticatesBearerJWT(t *testing.T) {
	t.Parallel()

	legacy := legacyOIDCAuth(t, "https://idp.example.com")
	repo := authrepomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, mock.Anything).RunAndReturn(
		func(_ context.Context, types []authdomain.Type) ([]*authdomain.Auth, error) {
			for _, queried := range types {
				if queried == legacy.Type {
					return []*authdomain.Auth{legacy}, nil
				}
			}
			return nil, nil
		})
	credentials := appauth.NewCredentialFinder(
		repo, cache.NewTTLMapManager(time.Hour), slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
	)
	jwtVal := &fakeTokenValidator{principal: &identity.Principal{Subject: "u1", Method: identity.MethodJWT}}
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		credentials,
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(legacy)}},
		jwtVal, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
	)

	id, err := resolveChain(t, resolver, map[string]string{
		"Authorization": "Bearer " + unsignedJWT(t, "https://idp.example.com"),
	})
	require.NoError(t, err)
	require.Equal(t, legacy.ID, id.AuthID)
	require.Equal(t, legacy.GatewayID, id.GatewayID)
	require.Equal(t, 1, jwtVal.calls)
}

func TestChain_TokenlessRequest_ChallengeMatchesBrokeringCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		auth             *authdomain.Auth
		wantResourceMeta bool
		wantDiagnostic   bool
	}{
		{
			name:             "broker-capable consumer advertises the login",
			auth:             brokerCapableOAuth2Auth(t, "https://idp.example.com"),
			wantResourceMeta: true,
		},
		{
			name:           "validate-only consumer explains the missing client",
			auth:           oauth2Auth(t, "https://idp.example.com", true),
			wantDiagnostic: true,
		},
		{
			name:           "legacy oidc consumer explains the missing client",
			auth:           legacyOIDCAuth(t, "https://legacy-idp.example.com"),
			wantDiagnostic: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain := middleware.NewChainIdentityResolver(
				fakeAPIKeyFinder{},
				fakeCredentialFinder{oauth2: []*authdomain.Auth{tt.auth}},
				fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(tt.auth)}},
				&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
			)
			app := fiber.New()
			app.Use(middleware.NewOAuthChallengeMiddleware().Middleware())
			app.Post("/runtime/mcp", func(c *fiber.Ctx) error {
				if _, err := chain.Resolve(c); err != nil {
					return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
				}
				return c.SendStatus(fiber.StatusOK)
			})

			res, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/runtime/mcp", nil))
			require.NoError(t, err)
			require.Equal(t, fiber.StatusUnauthorized, res.StatusCode)

			challenge := res.Header.Get(fiber.HeaderWWWAuthenticate)
			require.Equal(t, tt.wantResourceMeta, strings.Contains(challenge, "resource_metadata="),
				"resource_metadata pointer in %q", challenge)
			require.Equal(t, tt.wantDiagnostic, strings.Contains(challenge, `error="invalid_request"`),
				"diagnostic in %q", challenge)
			if tt.wantDiagnostic {
				require.Contains(t, challenge, "client_id")
			}
		})
	}
}
