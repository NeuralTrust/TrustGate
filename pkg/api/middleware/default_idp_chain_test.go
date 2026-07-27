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
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func defaultIdPForTest() *authdomain.Auth {
	return appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer:   "https://app.neuraltrust.ai/api/mcp/oauth",
		ClientID: "trustgate",
	})
}

// A session minted for the built-in default IdP resolves on an MCP path that
// has no identity provider of its own, and binds to the gateway carried in the
// gwid claim.
func TestChain_DefaultIdP_SessionResolvesWithGwidClaim(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw}}},
		&fakeTokenValidator{err: errors.New("must not be called")}, &fakeTokenValidator{}, &fakeMTLSValidator{},
		nil, verifier, nil, true,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "platform-user-1",
		"aud":       def.Config.OAuth2.Audiences,
		"authid":    appauth.DefaultIdPAuthID().String(),
		"gwid":      gw.String(),
		"token_use": "mcp_session",
	})

	id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)
	require.Equal(t, gw, id.GatewayID)
	require.Equal(t, appauth.DefaultIdPAuthID(), id.AuthID)
	require.Equal(t, "platform-user-1", id.Principal.Subject)
}

// Without a gwid claim there is no gateway to bind the default identity to, so
// the session is rejected.
func TestChain_DefaultIdP_SessionWithoutGwidRejected(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw}}},
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{},
		nil, verifier, nil, true,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "platform-user-1",
		"aud":       def.Config.OAuth2.Audiences,
		"authid":    appauth.DefaultIdPAuthID().String(),
		"token_use": "mcp_session",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

// When the default IdP is not enabled it is not added to the path scope, so a
// default-minted session is rejected even though the synthetic auth is a
// candidate.
func TestChain_DefaultIdP_DisabledRejectsSession(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw}}},
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{},
		nil, verifier, nil, false,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "platform-user-1",
		"aud":       def.Config.OAuth2.Audiences,
		"authid":    appauth.DefaultIdPAuthID().String(),
		"gwid":      gw.String(),
		"token_use": "mcp_session",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}

// An MCP consumer that configures its own oauth2 identity provider does not get
// the default added to its scope, so a default-minted session is rejected on
// that consumer's path.
func TestChain_DefaultIdP_NotAddedWhenConsumerHasOwnIdP(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	own := oauth2Auth(t, "https://idp.example.com", true)
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{own, def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(own)}},
		&fakeTokenValidator{}, &fakeTokenValidator{}, &fakeMTLSValidator{},
		nil, verifier, nil, true,
	)

	token := mintSession(t, signer, jwt.MapClaims{
		"sub":       "platform-user-1",
		"aud":       def.Config.OAuth2.Audiences,
		"authid":    appauth.DefaultIdPAuthID().String(),
		"gwid":      gw.String(),
		"token_use": "mcp_session",
	})

	_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
}
