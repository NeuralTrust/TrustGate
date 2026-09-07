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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authrepomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func validateOnlyOAuth2Auth(t *testing.T, issuer string, gatewayID ids.GatewayID) *authdomain.Auth {
	t.Helper()
	a := oauth2Auth(t, authdomain.OAuth2Config{
		Issuer:         issuer,
		Audiences:      []string{"trustgate"},
		RequiredScopes: []string{"mcp:use"},
	})
	a.ID = ids.New[ids.AuthKind]()
	a.GatewayID = gatewayID
	return a
}

func legacyOIDCAuth(issuer string, gatewayID ids.GatewayID) *authdomain.Auth {
	return &authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gatewayID,
		Name:      "legacy-oidc",
		Type:      authdomain.TypeOIDC,
		Enabled:   true,
		Config: authdomain.Config{OIDC: &authdomain.OIDCConfig{
			Issuer:         issuer,
			Audiences:      []string{"trustgate"},
			JWKSURL:        issuer + "/jwks",
			RequiredScopes: []string{"mcp:use"},
		}},
	}
}

func TestProtectedResourceOmitsAuthorizationServerForValidateOnlyAuth(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	idp := validateOnlyOAuth2Auth(t, "https://idp.example.com", gatewayID)
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/validate-only/mcp": {{GatewayID: gatewayID, Auths: []*authdomain.Auth{idp}}},
	}}
	svc := NewMetadataService(&fakeCredentialFinder{oauth2: []*authdomain.Auth{idp}}, paths, nil, newMemFlowStore())

	meta, err := svc.ProtectedResource(t.Context(), "https://gw.example.com", "https://gw.example.com/validate-only/mcp")
	require.NoError(t, err)
	require.Empty(t, meta.AuthorizationServers, "a validate-only provider cannot broker a login")
	require.Equal(t, []string{"mcp:use"}, meta.ScopesSupported, "scopes_supported describes the resource, not the AS")
}

func TestAuthorizationServerMetadataRequiresABrokerCapableProvider(t *testing.T) {
	t.Parallel()
	idp := validateOnlyOAuth2Auth(t, "https://idp.example.com", ids.New[ids.GatewayKind]())
	svc := NewMetadataService(&fakeCredentialFinder{oauth2: []*authdomain.Auth{idp}}, nil, nil, newMemFlowStore())

	_, err := svc.AuthorizationServer(t.Context(), "https://gw.example.com")
	require.ErrorIs(t, err, ErrNoAuthorizationServer)
}

func TestAuthorizeRejectsValidateOnlyResourceWithoutCallingTheIdP(t *testing.T) {
	t.Parallel()
	idpCalls := 0
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idpCalls++
		http.Error(w, "the identity provider must not be contacted", http.StatusInternalServerError)
	}))
	t.Cleanup(idp.Close)

	gatewayID := ids.New[ids.GatewayKind]()
	auth := validateOnlyOAuth2Auth(t, idp.URL, gatewayID)
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/validate-only/mcp": {{GatewayID: gatewayID, Auths: []*authdomain.Auth{auth}}},
	}}
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{auth}}
	proxy := NewAuthProxy(finder, paths, idp.Client(), newMemFlowStore(), nil, nil, nil)

	location, err := proxy.Authorize(t.Context(), "https://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            "https://gw.example.com/validate-only/mcp",
	})
	require.NoError(t, err)

	redirect, parseErr := url.Parse(location)
	require.NoError(t, parseErr)
	q := redirect.Query()
	require.Equal(t, "invalid_request", q.Get("error"))
	require.Contains(t, q.Get("error_description"), "client_id",
		"the diagnostic must name the missing pre-registered client")
	require.Zero(t, idpCalls, "selection must fail before any upstream IdP call")
}

func realCredentialFinder(t *testing.T, defaultIdP *authdomain.Auth, stored ...*authdomain.Auth) appauth.CredentialFinder {
	t.Helper()
	repo := authrepomocks.NewRepository(t)
	repo.EXPECT().FindEnabledByTypes(mock.Anything, mock.Anything).Return(stored, nil).Maybe()
	return appauth.NewCredentialFinder(
		repo,
		cache.NewTTLMapManager(time.Hour),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		defaultIdP,
	)
}

func TestOAuth2AuthsAreNotCapabilityGated(t *testing.T) {
	t.Parallel()
	validateOnly := validateOnlyOAuth2Auth(t, "https://idp.example.com", ids.New[ids.GatewayKind]())
	finder := realCredentialFinder(t, nil, validateOnly)

	auths, err := finder.OAuth2Auths(t.Context())
	require.NoError(t, err)
	require.Len(t, auths, 1)
	require.Equal(t, validateOnly.ID, auths[0].ID)
	require.False(t, auths[0].CanBrokerLogin())
}

func TestClientlessDefaultIdPIsValidateOnly(t *testing.T) {
	t.Parallel()
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://app.neuraltrust.ai/api/mcp/oauth",
	})
	require.NotNil(t, def)
	require.False(t, def.CanBrokerLogin(), "no client_id means no brokered login")

	_, err := pickSingleOAuth2([]*authdomain.Auth{def})
	require.ErrorIs(t, err, ErrNoAuthorizationServer, "the default must not win selection")

	p := &authProxy{credentials: &fakeCredentialFinder{defaultIdP: def}}
	_, err = p.gatewayScopedAuth(t.Context(), ids.New[ids.GatewayKind]())
	var oauthError *OAuthError
	require.True(t, errors.As(err, &oauthError))
	require.Equal(t, "invalid_request", oauthError.Code)

	svc := NewMetadataService(&fakeCredentialFinder{
		oauth2:     []*authdomain.Auth{def},
		defaultIdP: def,
	}, nil, nil, newMemFlowStore())
	meta, err := svc.ProtectedResource(t.Context(), "https://gw.example.com", "https://gw.example.com/mcp")
	require.NoError(t, err)
	require.Empty(t, meta.AuthorizationServers)
	_, err = svc.AuthorizationServer(t.Context(), "https://gw.example.com")
	require.ErrorIs(t, err, ErrNoAuthorizationServer)

	auths, err := realCredentialFinder(t, def).OAuth2Auths(t.Context())
	require.NoError(t, err)
	require.Len(t, auths, 1)
	require.True(t, appauth.IsDefaultIdP(auths[0]), "the default stays in the validation pool")
}

func TestProtectedResourceOmitsAuthorizationServerForLegacyOIDCAuth(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	idp := legacyOIDCAuth("https://idp.example.com", gatewayID)
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/legacy-oidc/mcp": {{GatewayID: gatewayID, Auths: []*authdomain.Auth{idp}}},
	}}
	svc := NewMetadataService(&fakeCredentialFinder{oauth2: []*authdomain.Auth{idp}}, paths, nil, newMemFlowStore())

	meta, err := svc.ProtectedResource(t.Context(), "https://gw.example.com", "https://gw.example.com/legacy-oidc/mcp")
	require.NoError(t, err)
	require.Empty(t, meta.AuthorizationServers, "a legacy oidc auth has no pre-registered client")
	require.Equal(t, []string{"mcp:use"}, meta.ScopesSupported,
		"the projected oidc config still describes the resource")
	require.Nil(t, idp.Config.OAuth2, "classification must not mutate the stored auth")
}

func TestLegacyOIDCAuthIsNeverSelectedAsProvider(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	legacy := legacyOIDCAuth("https://legacy-idp.example.com", gatewayID)
	broker := brokerCapableOAuth2Auth(t, authdomain.OAuth2Config{
		Issuer:    "https://idp.example.com",
		Audiences: []string{"trustgate"},
	})

	_, err := pickSingleOAuth2([]*authdomain.Auth{legacy})
	require.ErrorIs(t, err, ErrNoAuthorizationServer)

	got, err := pickSingleOAuth2([]*authdomain.Auth{legacy, broker})
	require.NoError(t, err, "a legacy oidc issuer must not make selection ambiguous")
	require.Same(t, broker, got)
}
