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
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
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

func TestChain_DefaultIdP_SessionResolvesWithGwidClaim(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw, Consumer: signInConsumer()}}},
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

func TestChain_DefaultIdP_NotAddedWhenConsumerHasAPIKey(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	apiKey, err := authdomain.NewAPIKeyAuth(gw, "api-key", true)
	require.NoError(t, err)
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(apiKey)}},
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

	_, err = resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated,
		"a platform login must not reach a consumer that requires its api key")
}

func TestChain_DefaultIdP_NotAddedWhenConsumerHasDisabledOAuth2(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	own := oauth2Auth(t, "https://idp.example.com", true)
	own.Enabled = false
	gw := own.GatewayID
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

func TestChain_DefaultIdP_SessionWithoutGwidRejected(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw, Consumer: signInConsumer()}}},
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

func TestChain_DefaultIdP_DisabledRejectsSession(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw, Consumer: signInConsumer()}}},
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

// Revoking a machine application's last api key must lock it down, not open it
// up: with no credential left the consumer is credential-less, and before this
// the built-in provider stepped in and let any platform login of the gateway
// enter it.
func TestChain_DefaultIdP_NotAddedForMachineConsumerWithoutCredential(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	machine := machineConsumer()
	machine.GatewayID = gw
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw, Consumer: machine}}},
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
	require.ErrorIs(t, err, apiresolver.ErrUnauthenticated,
		"a platform login must not reach an application that authenticates as itself")
}

// The Store is the sign-in identity by construction, so it keeps the built-in
// provider even though it carries no auth of its own.
func TestChain_DefaultIdP_ServesTheStoreConsumer(t *testing.T) {
	verifier, signer := sessionVerifier(t)
	def := defaultIdPForTest()
	gw := ids.New[ids.GatewayKind]()
	resolver := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
		fakePathResolver{matches: []appconsumer.PathMatch{{Consumer: consumerdomain.BuildStoreConsumer(ids.GatewayID{})}}},
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

	id, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
	require.NoError(t, err)
	require.Equal(t, gw, id.GatewayID)
}
