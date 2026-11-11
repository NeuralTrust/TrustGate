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

package a2a_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const stsIssuer = "https://sts.gateway.example"

func newSigner(t *testing.T) *infrasts.Signer {
	t.Helper()
	signer, err := infrasts.NewSigner(stsIssuer, "", nil)
	require.NoError(t, err)
	return signer
}

// verify checks a token against the signer's JWKS, as an agent would, and
// returns its claims.
func verify(t *testing.T, signer *infrasts.Signer, token string) jwt.MapClaims {
	t.Helper()
	keys, ok := signer.JWKS()["keys"].([]map[string]any)
	require.True(t, ok)
	decode := func(s any) *big.Int {
		raw, err := base64.RawURLEncoding.DecodeString(s.(string))
		require.NoError(t, err)
		return new(big.Int).SetBytes(raw)
	}
	pub := &rsa.PublicKey{N: decode(keys[0]["n"]), E: int(decode(keys[0]["e"]).Int64())}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithIssuer(stsIssuer), jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err)
	return claims
}

func bearer(t *testing.T, value string) string {
	t.Helper()
	token, ok := strings.CutPrefix(value, "Bearer ")
	require.True(t, ok, value)
	return token
}

func TestDelegationClaims(t *testing.T) {
	t.Parallel()
	signer := newSigner(t)
	creds := a2a.NewCredentials(sts.NewExchanger(signer, nil, nil), nil, nil, false)
	reg := a2aRegistry(t, a2a.Version10, "https://travel.example/a2a")
	reg.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeDelegation}
	rc := a2aConsumer(reg)
	app := consumerdomain.AppSubject(rc.Consumer.ID)

	cases := []struct {
		name      string
		principal *identity.Principal
		sub       string
		act       bool
		origIss   string
		kind      string
	}{
		{
			name:      "IdP user",
			principal: &identity.Principal{Subject: "u-42", Method: identity.MethodExternalJWT, Issuer: "https://login.microsoftonline.com/t/v2.0", Scopes: []string{"travel.read"}, Claims: map[string]any{"email": "u@example.com"}},
			sub:       "u-42", act: true, origIss: "https://login.microsoftonline.com/t/v2.0", kind: a2a.SubjectUser,
		},
		{
			name:      "user named by the application",
			principal: &identity.Principal{Subject: consumerdomain.EndUserSubject(rc.Consumer.ID, "user_123"), Method: identity.MethodAPIKey},
			sub:       app + ":user_123", act: true, kind: a2a.SubjectUser,
		},
		{
			name:      "application",
			principal: &identity.Principal{Subject: app, Method: identity.MethodAPIKey},
			sub:       app, kind: a2a.SubjectApp,
		},
	}
	for _, tc := range cases {
		header, trace, rpcErr := creds.For(context.Background(), rc, reg, tc.principal)
		require.Nil(t, rpcErr, tc.name)
		assert.Equal(t, a2a.IdentityTrace{Mode: "delegation", SubjectKind: tc.kind}, trace, tc.name)
		claims := verify(t, signer, bearer(t, header.Get("Authorization")))
		assert.Equal(t, tc.sub, claims["sub"], tc.name)
		assert.Equal(t, "https://travel.example/a2a", claims["aud"], tc.name)
		if tc.act {
			assert.Equal(t, map[string]any{"sub": app}, claims["act"], tc.name)
		} else {
			assert.NotContains(t, claims, "act", tc.name)
		}
		if tc.origIss != "" {
			assert.Equal(t, tc.origIss, claims["orig_iss"], tc.name)
		} else {
			assert.NotContains(t, claims, "orig_iss", tc.name)
		}
		assert.NotContains(t, claims, "email", tc.name)
	}
}

func TestDelegationTokenIsCachedPerAudience(t *testing.T) {
	t.Parallel()
	creds := a2a.NewCredentials(sts.NewExchanger(newSigner(t), nil, nil), nil, nil, false)
	reg := a2aRegistry(t, a2a.Version10, "https://travel.example/a2a")
	reg.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeDelegation}
	rc := a2aConsumer(reg)
	p := &identity.Principal{Subject: "u-42", Method: identity.MethodExternalJWT}

	first, _, rpcErr := creds.For(context.Background(), rc, reg, p)
	require.Nil(t, rpcErr)
	again, _, rpcErr := creds.For(context.Background(), rc, reg, p)
	require.Nil(t, rpcErr)
	assert.Equal(t, first.Get("Authorization"), again.Get("Authorization"))

	reg.A2ATarget.Auth.Audience = "https://travel.example/other"
	other, _, rpcErr := creds.For(context.Background(), rc, reg, p)
	require.Nil(t, rpcErr)
	assert.NotEqual(t, first.Get("Authorization"), other.Get("Authorization"))
}

func TestDelegationRefusedOnAnEphemeralKey(t *testing.T) {
	t.Parallel()
	creds := a2a.NewCredentials(sts.NewExchanger(newSigner(t), nil, nil), nil, nil, true)
	reg := a2aRegistry(t, a2a.Version10, "https://travel.example/a2a")
	reg.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeDelegation}
	_, _, rpcErr := creds.For(context.Background(), a2aConsumer(reg), reg, &identity.Principal{Subject: "u-42"})
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.ReasonSigningKeyUnavailable, reasonOf(t, rpcErr))
}

func TestUserTokenPatternsNeedAnIdPUser(t *testing.T) {
	t.Parallel()
	creds := a2a.NewCredentials(sts.NewExchanger(newSigner(t), nil, nil), nil, nil, false)
	for _, pattern := range []registrydomain.MCPExchangePattern{registrydomain.ExchangeOBO, registrydomain.ExchangeTokenExchange} {
		reg := a2aRegistry(t, a2a.Version10, "https://travel.example/a2a")
		reg.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeExchange, Pattern: pattern, Scope: "api://travel/.default"}
		rc := a2aConsumer(reg)
		for _, p := range []*identity.Principal{
			{Subject: consumerdomain.AppSubject(rc.Consumer.ID), Method: identity.MethodAPIKey},
			{Subject: consumerdomain.EndUserSubject(rc.Consumer.ID, "user_123"), Method: identity.MethodAPIKey},
		} {
			_, trace, rpcErr := creds.For(context.Background(), rc, reg, p)
			require.NotNil(t, rpcErr, pattern)
			assert.Equal(t, a2a.CodeIdentityRequired, rpcErr.Code, pattern)
			assert.Equal(t, string(pattern), trace.Mode)
		}
	}
}

func TestClientCredentialsTokenIsCachedUntilTheRegistryChanges(t *testing.T) {
	t.Parallel()
	provider := oauthmocks.NewProviderClient(t)
	provider.EXPECT().ClientCredentials(mock.Anything, mock.Anything).
		Return(&appoauth.ProviderToken{AccessToken: "cc-1", ExpiresAt: time.Now().Add(time.Hour)}, nil).Once()
	provider.EXPECT().ClientCredentials(mock.Anything, mock.Anything).
		Return(&appoauth.ProviderToken{AccessToken: "cc-2"}, nil).Once()
	creds := a2a.NewCredentials(nil, provider, nil, false)
	reg := a2aRegistry(t, a2a.Version03, "https://travel.example/a2a")
	reg.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeClientCredentials, ClientID: "id", ClientSecret: "s", TokenURL: "https://idp.example/token"}
	rc := a2aConsumer(reg)

	for range 2 {
		header, trace, rpcErr := creds.For(context.Background(), rc, reg, nil)
		require.Nil(t, rpcErr)
		assert.Equal(t, "Bearer cc-1", header.Get("Authorization"))
		assert.Equal(t, a2a.IdentityTrace{Mode: "client_credentials", SubjectKind: a2a.SubjectApp}, trace)
	}
	reg.UpdatedAt = reg.UpdatedAt.Add(time.Second)
	header, _, rpcErr := creds.For(context.Background(), rc, reg, nil)
	require.Nil(t, rpcErr)
	assert.Equal(t, "Bearer cc-2", header.Get("Authorization"))
}
