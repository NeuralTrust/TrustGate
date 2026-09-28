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
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// A refused session token is one opaque 401 on the wire, so the pod log is the
// only place the reason can survive. These cases are the ones that cost an
// afternoon in a live environment: they look identical from outside and are
// told apart only by what gets written here.
func TestChain_DefaultIdP_RejectionNamesItsReason(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	def := defaultIdPForTest()

	cases := []struct {
		name   string
		claims func() jwt.MapClaims
		reason string
	}{
		{
			name: "audience the gateway does not accept",
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"sub": "u1", "aud": []string{"someone-elses-api"},
					"authid": appauth.DefaultIdPAuthID().String(),
					"gwid":   gw.String(), "token_use": "mcp_session",
				}
			},
			reason: "audience mismatch",
		},
		{
			name: "a platform token that was never an MCP session",
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"sub": "u1", "aud": def.Config.OAuth2.Audiences,
					"authid": appauth.DefaultIdPAuthID().String(),
					"gwid":   gw.String(), "token_use": "access",
				}
			},
			reason: "token is not an mcp session",
		},
		{
			name: "a session that names no gateway",
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"sub": "u1", "aud": def.Config.OAuth2.Audiences,
					"authid": appauth.DefaultIdPAuthID().String(), "token_use": "mcp_session",
				}
			},
			reason: "default-idp session carries no usable gwid",
		},
		{
			name: "a session minted against an identity provider this gateway does not run",
			claims: func() jwt.MapClaims {
				return jwt.MapClaims{
					"sub": "u1", "aud": def.Config.OAuth2.Audiences,
					"authid": ids.New[ids.AuthKind]().String(),
					"gwid":   gw.String(), "token_use": "mcp_session",
				}
			},
			reason: "authid matches no enabled oauth2 auth",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier, signer := sessionVerifier(t)
			resolver := middleware.NewChainIdentityResolver(
				fakeAPIKeyFinder{},
				fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def},
				fakePathResolver{matches: []appconsumer.PathMatch{{GatewayID: gw, Consumer: signInConsumer()}}},
				&fakeTokenValidator{err: errors.New("must not be called")}, &fakeTokenValidator{}, &fakeMTLSValidator{},
				nil, verifier, nil, true,
			)
			token := mintSession(t, signer, tc.claims())

			var logged bytes.Buffer
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
			t.Cleanup(func() { slog.SetDefault(restore) })

			_, err := resolveChain(t, resolver, map[string]string{"Authorization": "Bearer " + token})
			require.Error(t, err)
			require.Contains(t, logged.String(), tc.reason)
		})
	}
}
