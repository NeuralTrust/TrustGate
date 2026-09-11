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
	"net/http"
	"net/url"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeSkipsValidationOnlyProviderWithSameIssuer(t *testing.T) {
	for _, validationFirst := range []bool{true, false} {
		for _, resourceScoped := range []bool{true, false} {
			name := "gateway"
			if resourceScoped {
				name = "resource"
			}
			if validationFirst {
				name += "/validation-first"
			} else {
				name += "/interactive-first"
			}
			t.Run(name, func(t *testing.T) {
				idp, captured := fakeIdP(t)
				interactive := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idp.URL, ClientID: "interactive-client", Audiences: []string{"interactive-api"}})
				validation := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idp.URL, Audiences: []string{"machine-api"}})
				validation.GatewayID = interactive.GatewayID
				validation.Config.OAuth2.ClientID = ""
				require.False(t, validation.Config.OAuth2.ConflictsWith(interactive.Config.OAuth2))
				auths := []*authdomain.Auth{interactive, validation}
				if validationFirst {
					auths[0], auths[1] = auths[1], auths[0]
				}
				resource := ""
				paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{}}
				if resourceScoped {
					resource = "https://gateway.example/consumer/mcp"
					paths.byPath["/consumer/mcp"] = []appconsumer.PathMatch{{GatewayID: interactive.GatewayID, Auths: auths}}
				}
				proxy := NewAuthProxy(&fakeCredentialFinder{oauth2: auths}, paths, http.DefaultClient, newMemFlowStore(), nil, nil, nil)
				location, err := proxy.Authorize(t.Context(), "https://gateway.example", AuthorizeRequest{
					ResponseType: "code", RedirectURI: "https://client.example/callback", CodeChallenge: s256("verifier"), CodeChallengeMethod: "S256", Resource: resource,
				})
				require.NoError(t, err)
				redirect, err := url.Parse(location)
				require.NoError(t, err)
				require.Equal(t, "interactive-client", redirect.Query().Get("client_id"))
				clientRedirect, err := proxy.Callback(t.Context(), "https://gateway.example", redirect.Query().Get("state"), "idp-code", "", "")
				require.NoError(t, err)
				require.Equal(t, "interactive-client", captured.Get("client_id"))
				token, err := proxy.Exchange(t.Context(), "https://gateway.example", TokenRequest{
					GrantType: "authorization_code", Code: exchangeCodeFrom(t, clientRedirect), RedirectURI: "https://client.example/callback", CodeVerifier: "verifier",
				})
				require.NoError(t, err)
				require.Equal(t, "idp-access-token", token["access_token"])

			})
		}
	}
}

func TestAuthorizeRejectsValidationOnlyResource(t *testing.T) {
	idp, _ := fakeIdP(t)
	validation := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idp.URL})
	validation.Config.OAuth2.ClientID = ""
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/consumer/mcp": {{GatewayID: validation.GatewayID, Auths: []*authdomain.Auth{validation}}},
	}}
	store := newMemFlowStore()
	proxy := NewAuthProxy(&fakeCredentialFinder{oauth2: []*authdomain.Auth{validation}}, paths, http.DefaultClient, store, nil, nil, nil)
	location, err := proxy.Authorize(t.Context(), "https://gateway.example", AuthorizeRequest{
		ResponseType: "code", RedirectURI: "https://client.example/callback", CodeChallenge: s256("verifier"), CodeChallengeMethod: "S256", Resource: "https://gateway.example/consumer/mcp",
	})
	require.NoError(t, err)
	assertClientToldOfError(t, location, "https://client.example/callback", "invalid_target")
	require.Empty(t, store.pending)
}

func TestCallbackRejectsProviderChangedToValidationOnly(t *testing.T) {
	idp, captured := fakeIdP(t)
	auth := enabledOAuth2Auth(t, authdomain.OAuth2Config{Issuer: idp.URL, ClientID: "interactive-client"})
	proxy := NewAuthProxy(&fakeCredentialFinder{oauth2: []*authdomain.Auth{auth}}, nil, http.DefaultClient, newMemFlowStore(), nil, nil, nil)
	location, err := proxy.Authorize(t.Context(), "https://gateway.example", AuthorizeRequest{
		ResponseType: "code", RedirectURI: "https://client.example/callback", CodeChallenge: s256("verifier"), CodeChallengeMethod: "S256",
	})
	require.NoError(t, err)
	redirect, err := url.Parse(location)
	require.NoError(t, err)
	auth.Config.OAuth2.ClientID = ""

	location, err = proxy.Callback(t.Context(), "https://gateway.example", redirect.Query().Get("state"), "idp-code", "", "")
	var protocolErr *OAuthError
	require.ErrorAs(t, err, &protocolErr)
	require.Equal(t, "invalid_request", protocolErr.Code)
	require.Contains(t, protocolErr.Description, "no longer supports interactive login")
	require.Empty(t, location)
	require.Empty(t, *captured)
}
