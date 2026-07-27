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
	"errors"
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
	got, err = pickSingleOAuth2([]*authdomain.Auth{real, realOAuth2(t, "https://idp2.example.com"), def})
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
