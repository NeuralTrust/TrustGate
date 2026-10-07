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
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

func realOAuth2(t *testing.T, issuer string) *authdomain.Auth {
	return oauth2Auth(t, authdomain.OAuth2Config{Issuer: issuer})
}

func TestPickSingleOAuth2_DefaultIsFallbackOnly(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth", ClientID: "tg",
	})
	real := realOAuth2(t, "https://idp.example.com")

	// Only the default is present: it is returned as the fallback.
	got, err := pickSingleOAuth2([]*authdomain.Auth{def})
	require.NoError(t, err)
	require.True(t, appauth.IsDefaultIdP(got))

	// A real provider wins over the default (no ambiguity).
	got, err = pickSingleOAuth2([]*authdomain.Auth{real, def})
	require.NoError(t, err)
	require.Equal(t, real.ID, got.ID)

	// The default never causes ambiguity.
	_, err = pickSingleOAuth2([]*authdomain.Auth{real, realOAuth2(t, "https://idp2.example.com"), def})
	require.ErrorIs(t, err, ErrAmbiguousAuthorizationServer)

	// No providers at all.
	_, err = pickSingleOAuth2(nil)
	require.ErrorIs(t, err, ErrNoAuthorizationServer)
}

func TestGatewayScopedAuth_FallsBackToDefault(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth", ClientID: "tg",
	})
	gw := ids.New[ids.GatewayKind]()
	p := &authProxy{credentials: &fakeCredentialFinder{defaultIdP: def}}

	auth, err := p.gatewayScopedAuth(t.Context(), gw)
	require.NoError(t, err)
	require.True(t, appauth.IsDefaultIdP(auth))
	// The default is bound to the addressed gateway.
	require.Equal(t, gw, auth.GatewayID)
}

// A consumer that authenticates with its own credential gets no identity
// provider at all: brokering a login for it would produce a session the auth
// chain refuses, so the flow is rejected before it starts.
func TestAuthForResource_CredentialProtectedConsumerGetsNoIdP(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth", ClientID: "tg",
	})
	gw := ids.New[ids.GatewayKind]()
	apiKey, err := authdomain.NewAPIKeyAuth(gw, "key", true, nil)
	require.NoError(t, err)
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/api-key/mcp":  {{GatewayID: gw, Consumer: mcpConsumer(gw), Auths: []*authdomain.Auth{apiKey}}},
		"/nil-consumer": {{GatewayID: gw, Auths: []*authdomain.Auth{apiKey}}},
		"/bare/mcp":     {{GatewayID: gw, Consumer: consumerdomain.BuildStoreConsumer(gw)}},
	}}
	p := &authProxy{credentials: &fakeCredentialFinder{defaultIdP: def}, paths: paths}

	for _, resource := range []string{"https://gw.example.com/api-key/mcp", "https://gw.example.com/nil-consumer"} {
		_, err = p.authForResource(t.Context(), resource)
		var oauthError *OAuthError
		require.True(t, errors.As(err, &oauthError), resource)
		require.Equal(t, "invalid_target", oauthError.Code, resource)
	}

	// A sign-in consumer with no credential of its own still reaches the default.
	auth, err := p.authForResource(t.Context(), "https://gw.example.com/bare/mcp")
	require.NoError(t, err)
	require.True(t, appauth.IsDefaultIdP(auth))
}

// A login is brokered through the built-in default only where the request-time
// auth chain admits it (appconsumer.DefaultIdPAdmitted): any other answer mints
// a session the chain refuses, and the client loops on 401 (RUN-1787).
func TestAuthForResource_BrokersDefaultOnlyWhereTheChainAdmitsIt(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth", ClientID: "tg",
	})
	apiKey, err := authdomain.NewAPIKeyAuth(gw, "residual", true, nil)
	require.NoError(t, err)
	disabledKey, err := authdomain.NewAPIKeyAuth(gw, "disabled", false, nil)
	require.NoError(t, err)
	disabledIdP := &authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gw,
		Type:      authdomain.TypeOAuth2,
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer:  "https://idp.example.com",
			JWKSURL: "https://idp.example.com/jwks",
		}},
	}
	mtls := &authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gw,
		Type:      authdomain.TypeMTLS,
		Enabled:   true,
	}
	validationOnlyIdP := &authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gw,
		Type:      authdomain.TypeOAuth2,
		Enabled:   true,
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer:  "https://idp.example.com",
			JWKSURL: "https://idp.example.com/jwks",
		}},
	}

	// Only the Store is entered by people signing in with nothing attached, so
	// only the Store may be rescued by the built-in identity provider. Every
	// other consumer is entered by what it holds: bringing a credential, or
	// holding none, both keep the default out.
	tests := []struct {
		name        string
		store       bool
		auths       []*authdomain.Auth
		wantDefault bool
	}{
		{name: "store consumer with no links", store: true, wantDefault: true},
		{name: "store consumer with only a disabled api key", store: true, auths: []*authdomain.Auth{disabledKey}, wantDefault: true},
		// An enabled credential is a way in the chain honours, and while it is
		// there the chain keeps the default out.
		{name: "store consumer with an api key", store: true, auths: []*authdomain.Auth{apiKey}},
		{name: "store consumer with a client certificate", store: true, auths: []*authdomain.Auth{mtls}},
		// The operator pinned this provider; overriding an explicit pin with the
		// built-in default would widen who gets in on the gateway's own
		// initiative, so it stays a dead end (RUN-1501).
		{name: "store consumer with a validation only idp stays a dead end", store: true, auths: []*authdomain.Auth{validationOnlyIdP}},
		{name: "store consumer whose only idp is disabled", store: true, auths: []*authdomain.Auth{disabledIdP}},
		{name: "an ordinary consumer brings its own credential", auths: []*authdomain.Auth{apiKey}},
		{name: "an ordinary consumer brings its own client certificate", auths: []*authdomain.Auth{mtls}},
		{name: "an ordinary consumer with nothing attached"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cons := mcpConsumer(gw)
			if tt.store {
				cons = consumerdomain.BuildStoreConsumer(gw)
			}
			paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
				"/v1/mcp/app": {{GatewayID: gw, Consumer: cons, Auths: tt.auths}},
			}}
			p := &authProxy{credentials: &fakeCredentialFinder{defaultIdP: def}, paths: paths}

			auth, err := p.authForResource(t.Context(), "https://gw.example.com/v1/mcp/app")
			if tt.wantDefault {
				require.NoError(t, err)
				require.True(t, appauth.IsDefaultIdP(auth))
				require.Equal(t, gw, auth.GatewayID)
				return
			}
			var oauthError *OAuthError
			require.True(t, errors.As(err, &oauthError))
			require.Equal(t, "invalid_target", oauthError.Code)
		})
	}
}

func entraSignInIdentity(t *testing.T, gw ids.GatewayID) *authdomain.Auth {
	t.Helper()
	a := enabledOAuth2Auth(t, authdomain.OAuth2Config{
		Issuer:         "https://login.microsoftonline.com/tid/v2.0",
		Audiences:      []string{"api://gw"},
		ClientID:       "entra-app",
		RequiredScopes: []string{"mcp.access"},
	})
	a.GatewayID = gw
	return a
}

// A sign-in consumer with no identity provider of its own is admitted by the
// auth chain only through the built-in default, so turning sign-in on for an
// unattached Entra identity on the same gateway must not divert its login
// there: the Entra session would be refused and the client would loop on 401.
func TestAuthForResource_UnpinnedSignInConsumerBrokersDefault(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth", ClientID: "tg",
	})
	entra := entraSignInIdentity(t, gw)
	require.True(t, entra.Config.OAuth2.Interactive())
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/v1/mcp/store": {{GatewayID: gw, Consumer: consumerdomain.BuildStoreConsumer(gw)}},
	}}
	p := &authProxy{
		credentials: &fakeCredentialFinder{oauth2: []*authdomain.Auth{entra}, defaultIdP: def},
		paths:       paths,
	}

	auth, err := p.authForResource(t.Context(), "https://gw.example.com/v1/mcp/store")
	require.NoError(t, err)
	require.True(t, appauth.IsDefaultIdP(auth))
	require.Equal(t, gw, auth.GatewayID)
}

func TestGatewayScopedAuth_NoDefaultKeepsError(t *testing.T) {
	p := &authProxy{credentials: &fakeCredentialFinder{}}
	_, err := p.gatewayScopedAuth(t.Context(), ids.New[ids.GatewayKind]())
	var oauthError *OAuthError
	require.True(t, errors.As(err, &oauthError))
	require.Equal(t, "invalid_request", oauthError.Code)
}

// A gateway that hosts several operator-configured IdPs is normally ambiguous,
// but when the built-in default is configured a consumer that pinned none of
// them resolves to the default instead of failing with invalid_target — this is
// how a consumer opts into the default while other IdPs coexist on the gateway.
func TestGatewayScopedAuth_AmbiguousFallsBackToDefault(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth", ClientID: "tg",
	})
	gw := ids.New[ids.GatewayKind]()
	authA := realOAuth2(t, "https://idp-a.example.com")
	authA.GatewayID = gw
	authB := realOAuth2(t, "https://idp-b.example.com")
	authB.GatewayID = gw
	p := &authProxy{credentials: &fakeCredentialFinder{
		oauth2:     []*authdomain.Auth{authA, authB},
		defaultIdP: def,
	}}

	auth, err := p.gatewayScopedAuth(t.Context(), gw)
	require.NoError(t, err)
	require.True(t, appauth.IsDefaultIdP(auth))
	require.Equal(t, gw, auth.GatewayID)
}

// Without a default configured, the same multi-IdP gateway stays a hard
// invalid_target error: the gateway never silently picks one of several
// operator-configured IdPs.
func TestGatewayScopedAuth_AmbiguousNoDefaultStaysError(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	authA := realOAuth2(t, "https://idp-a.example.com")
	authA.GatewayID = gw
	authB := realOAuth2(t, "https://idp-b.example.com")
	authB.GatewayID = gw
	p := &authProxy{credentials: &fakeCredentialFinder{oauth2: []*authdomain.Auth{authA, authB}}}

	_, err := p.gatewayScopedAuth(t.Context(), gw)
	var oauthError *OAuthError
	require.True(t, errors.As(err, &oauthError))
	require.Equal(t, "invalid_target", oauthError.Code)
}

// The consent detour must target the gateway captured at authorize time, not
// the default IdP's (nil) gateway — otherwise the upstream-connect screen never
// opens for MCP consumers that rely on the built-in default.
func TestCallbackDefaultIdPConsentUsesEffectiveGateway(t *testing.T) {
	accessToken := unsignedJWT(t, map[string]any{"sub": "platform-user-1"})
	idp := fakeIdPWithToken(t, accessToken)
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{Issuer: idp.URL, ClientID: "trustgate"})
	require.True(t, def.GatewayID.IsNil(), "the default IdP has no gateway of its own")

	store := newMemFlowStore()
	chainer := &fakeChainer{url: "http://localhost:8082/oMTXK0qG/mcp/connect?ticket=tk"}
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, store, chainer, nil, nil)

	gw := ids.New[ids.GatewayKind]()
	state := "state-1"
	require.NoError(t, store.SavePending(context.Background(), state, PendingAuthorization{
		ClientID:      "trustgate",
		RedirectURI:   "http://localhost:8082/oauth/callback",
		State:         "client-state",
		CodeChallenge: "chal",
		CodeVerifier:  "verifier",
		Resource:      "http://localhost:8082/oMTXK0qG/mcp",
		AuthID:        appauth.DefaultIdPAuthID().String(),
		GatewayID:     gw.String(),
	}))

	loc, err := proxy.Callback(context.Background(), "http://localhost:8082", state, "the-code", "", "")
	require.NoError(t, err)
	require.Equal(t, chainer.url, loc, "callback must detour to the upstream-connect page")
	require.Equal(t, 1, chainer.calls)
	require.Equal(t, gw, chainer.gatewayID, "consent detour must use the addressed gateway, not the default's nil gateway")
	require.Equal(t, "platform-user-1", chainer.sub)
}

func TestCallbackDefaultIdPCapturesEmailFromAccessToken(t *testing.T) {
	accessToken := unsignedJWT(t, map[string]any{
		"sub":   "fff9c76a-52e8-416f-8b6a-489000000001",
		"email": "ada@neuraltrust.ai",
	})
	idp := fakeIdPWithToken(t, accessToken)
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{Issuer: idp.URL, ClientID: "trustgate"})
	store := newMemFlowStore()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, nil, http.DefaultClient, store, nil, newTestSigner(t), nil)

	gw := ids.New[ids.GatewayKind]()
	state := "state-email"
	require.NoError(t, store.SavePending(context.Background(), state, PendingAuthorization{
		ClientID:      "trustgate",
		RedirectURI:   "http://localhost:8082/oauth/callback",
		State:         "client-state",
		CodeChallenge: "chal",
		CodeVerifier:  "verifier",
		Resource:      "http://localhost:8082/oMTXK0qG/mcp",
		AuthID:        appauth.DefaultIdPAuthID().String(),
		GatewayID:     gw.String(),
	}))

	loc, err := proxy.Callback(context.Background(), "http://localhost:8082", state, "the-code", "", "")
	require.NoError(t, err)
	require.Contains(t, loc, "code=")

	grant := store.peekFirstGrant()
	require.NotNil(t, grant)
	require.Equal(t, "fff9c76a-52e8-416f-8b6a-489000000001", grant.Subject)
	require.Equal(t, "ada@neuraltrust.ai", grant.Email)
}
