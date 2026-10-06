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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/stretchr/testify/require"
)

// RUN-1764: an MCP client lost its connector to a 401 that left nothing in the
// pod log, so nobody could tell whether the gateway refused a good token or the
// client sent none. Every refusal outside a session token names its reason too.
func TestChain_CredentialRejectionNamesItsReason(t *testing.T) {
	idp := oauth2Auth(t, "https://idp.example.com", true)
	token := unsignedJWT(t, "https://idp.example.com")

	cases := []struct {
		name    string
		apiKeys fakeAPIKeyFinder
		jwt     *fakeTokenValidator
		headers map[string]string
		level   string
		reason  string
	}{
		{
			name:   "no credential at all",
			jwt:    &fakeTokenValidator{},
			level:  "INFO",
			reason: "no credential presented",
		},
		{
			name:    "a token from an issuer the path does not accept",
			jwt:     &fakeTokenValidator{},
			headers: map[string]string{"Authorization": "Bearer " + unsignedJWT(t, "https://other.example.com")},
			level:   "WARN",
			reason:  "token issuer matches no oauth2 auth on the path",
		},
		{
			name:    "a token the identity provider's keys reject",
			jwt:     &fakeTokenValidator{err: errors.New("token is expired")},
			headers: map[string]string{"Authorization": "Bearer " + token},
			level:   "WARN",
			reason:  "token does not validate",
		},
		{
			name:    "an api key nobody issued",
			apiKeys: fakeAPIKeyFinder{err: authdomain.ErrNotFound},
			jwt:     &fakeTokenValidator{},
			headers: map[string]string{apiresolver.HeaderAPIKey: "ag_unknown"},
			level:   "WARN",
			reason:  "api key is unknown",
		},
		{
			name:    "an api key past its expiry",
			apiKeys: fakeAPIKeyFinder{err: authdomain.ErrExpired},
			jwt:     &fakeTokenValidator{},
			headers: map[string]string{apiresolver.HeaderAPIKey: "ag_expired"},
			level:   "WARN",
			reason:  "api key has expired",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := middleware.NewChainIdentityResolver(
				tc.apiKeys, fakeCredentialFinder{oauth2: []*authdomain.Auth{idp}}, nil,
				tc.jwt, &fakeTokenValidator{}, &fakeMTLSValidator{}, nil, nil, nil, false,
			)

			var logged bytes.Buffer
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, &slog.HandlerOptions{Level: slog.LevelInfo})))
			t.Cleanup(func() { slog.SetDefault(restore) })

			_, err := resolveChain(t, resolver, tc.headers)
			require.ErrorIs(t, err, apiresolver.ErrUnauthenticated)
			out := logged.String()
			require.Contains(t, out, `"msg":"mcp auth: credential rejected"`)
			require.Contains(t, out, `"reason":"`+tc.reason+`"`)
			require.Contains(t, out, `"level":"`+tc.level+`"`)
			for _, secret := range []string{token, "ag_unknown", "ag_expired"} {
				require.False(t, strings.Contains(out, secret), "the log carries the credential itself")
			}
		})
	}
}
