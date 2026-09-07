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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestChain_DefaultIdPLoginCapabilityDoesNotRestrictValidation(t *testing.T) {
	t.Parallel()
	for _, clientID := range []string{"", "mcp-client"} {
		t.Run("client="+clientID, func(t *testing.T) {
			t.Parallel()
			provider := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
				Issuer: "https://platform.example.com", ClientID: clientID,
				JWKSURL: "https://platform.example.com/jwks", Audiences: []string{"mcp"},
			})
			require.NotNil(t, provider)
			for _, ownCredential := range []bool{false, true} {
				name := "no consumer credential"
				var auths []*authdomain.Auth
				if ownCredential {
					name = "consumer API key"
					key, err := authdomain.NewAPIKeyAuth(ids.New[ids.GatewayKind](), "key", true)
					require.NoError(t, err)
					auths = []*authdomain.Auth{key}
				}
				t.Run(name, func(t *testing.T) {
					validator := &fakeTokenValidator{principal: &identity.Principal{Subject: "user", Method: identity.MethodJWT}}
					chain := middleware.NewChainIdentityResolver(
						fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{provider}, defaultIdP: provider},
						fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(auths...)}},
						validator, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, true,
					)
					app := fiber.New()
					app.Use(middleware.NewOAuthChallengeMiddleware().Middleware())
					app.Post("/runtime/mcp", func(c *fiber.Ctx) error {
						if _, err := chain.Resolve(c); err != nil {
							return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
						}
						return c.SendStatus(fiber.StatusOK)
					})
					response, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/runtime/mcp", nil))
					require.NoError(t, err)
					require.NoError(t, response.Body.Close())
					require.Equal(t, fiber.StatusUnauthorized, response.StatusCode)
					challenge := response.Header.Get(fiber.HeaderWWWAuthenticate)
					require.Equal(t, !ownCredential && clientID != "", strings.Contains(challenge, "resource_metadata="))
					require.Equal(t, !ownCredential && clientID == "", strings.Contains(challenge, "client_id"))
					req := httptest.NewRequest(fiber.MethodPost, "/runtime/mcp", nil)
					req.Header.Set(fiber.HeaderAuthorization, "Bearer "+unsignedJWT(t, provider.Config.OAuth2.Issuer))
					response, err = app.Test(req)
					require.NoError(t, err)
					require.NoError(t, response.Body.Close())
					if ownCredential {
						require.Equal(t, fiber.StatusUnauthorized, response.StatusCode)
						require.Zero(t, validator.calls)
					} else {
						require.Equal(t, fiber.StatusOK, response.StatusCode)
						require.Equal(t, 1, validator.calls)
					}
				})
			}
		})
	}
}

func TestChain_InlineKeysSelectJWTValidationAlongsideIntrospection(t *testing.T) {
	t.Parallel()
	provider := oauth2Auth(t, "https://idp.example.com", false)
	provider.Config.OAuth2.PublicKeys = []string{"inline-public-key"}
	jwtValidator := &fakeTokenValidator{principal: &identity.Principal{Subject: "user", Method: identity.MethodJWT}}
	introValidator := &fakeTokenValidator{}
	chain := middleware.NewChainIdentityResolver(
		fakeAPIKeyFinder{}, fakeCredentialFinder{oauth2: []*authdomain.Auth{provider}},
		fakePathResolver{matches: []appconsumer.PathMatch{pathMatchWith(provider)}},
		jwtValidator, introValidator, &fakeMTLSValidator{}, nil, nil, nil, false,
	)
	got, err := resolveChain(t, chain, map[string]string{"Authorization": "Bearer " + unsignedJWT(t, provider.Config.OAuth2.Issuer)})
	require.NoError(t, err)
	require.Equal(t, identity.MethodJWT, got.Principal.Method)
	require.Equal(t, 1, jwtValidator.calls)
	require.Zero(t, introValidator.calls)
}
