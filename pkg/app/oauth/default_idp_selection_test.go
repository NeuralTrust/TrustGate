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
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
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
