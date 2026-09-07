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

package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "https://app.neuraltrust.ai"
	testAudience = "trustgate-admin"
	testKID      = "kid-1"
)

func publicKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newVerifier(t *testing.T, key *rsa.PrivateKey) jwt.ServiceVerifier {
	t.Helper()
	verifier, err := jwt.NewServiceVerifier(config.AdminM2MConfig{
		Issuer:      testIssuer,
		Audience:    testAudience,
		MaxTokenTTL: 15 * time.Minute,
		PublicKeys:  []config.AdminM2MPublicKey{{KID: testKID, PEM: publicKeyPEM(t, key)}},
	})
	require.NoError(t, err)
	return verifier
}

func validClaims() *jwt.ServiceClaims {
	now := time.Now()
	return &jwt.ServiceClaims{
		TokenUse:  jwt.TokenUseAdminM2M,
		TenantID:  "acme",
		GatewayID: "11111111-1111-1111-1111-111111111111",
		Scopes:    []string{"consumers:write"},
		RegisteredClaims: golangjwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  golangjwt.ClaimStrings{testAudience},
			Subject:   "service-account:cred-1",
			IssuedAt:  golangjwt.NewNumericDate(now),
			ExpiresAt: golangjwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, claims *jwt.ServiceClaims) string {
	t.Helper()
	token := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestServiceVerifier_AcceptsWellFormedToken(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	claims, err := newVerifier(t, key).Verify(signRS256(t, key, validClaims()))
	require.NoError(t, err)
	require.Equal(t, "acme", claims.TenantID)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", claims.GatewayID)
	require.Equal(t, []string{"consumers:write"}, claims.Scopes)
}

func TestServiceVerifier_Rejects(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{
			name: "unknown signing key",
			token: func(t *testing.T) string {
				return signRS256(t, other, validClaims())
			},
		},
		{
			name: "missing kid",
			token: func(t *testing.T) string {
				token := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, validClaims())
				signed, err := token.SignedString(key)
				require.NoError(t, err)
				return signed
			},
		},
		{
			name: "wrong audience",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.Audience = golangjwt.ClaimStrings{"someone-else"}
				return signRS256(t, key, claims)
			},
		},
		{
			name: "wrong issuer",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.Issuer = "https://evil.example"
				return signRS256(t, key, claims)
			},
		},
		{
			name: "expired",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.IssuedAt = golangjwt.NewNumericDate(time.Now().Add(-time.Hour))
				claims.ExpiresAt = golangjwt.NewNumericDate(time.Now().Add(-time.Minute))
				return signRS256(t, key, claims)
			},
		},
		{
			name: "no expiration",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.ExpiresAt = nil
				return signRS256(t, key, claims)
			},
		},
		{
			name: "lifetime beyond ceiling",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.ExpiresAt = golangjwt.NewNumericDate(time.Now().Add(24 * time.Hour))
				return signRS256(t, key, claims)
			},
		},
		{
			name: "wrong token use",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.TokenUse = "config-sync"
				return signRS256(t, key, claims)
			},
		},
		{
			name: "missing gateway binding",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.GatewayID = ""
				return signRS256(t, key, claims)
			},
		},
		{
			name: "missing tenant",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.TenantID = ""
				return signRS256(t, key, claims)
			},
		},
		{
			name: "no scopes",
			token: func(t *testing.T) string {
				claims := validClaims()
				claims.Scopes = nil
				return signRS256(t, key, claims)
			},
		},
		{
			name: "hmac downgrade",
			token: func(t *testing.T) string {
				signed, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, validClaims()).
					SignedString([]byte(publicKeyPEM(t, key)))
				require.NoError(t, err)
				return signed
			},
		},
	}

	verifier := newVerifier(t, key)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := verifier.Verify(tc.token(t))
			require.ErrorIs(t, err, jwt.ErrInvalidServiceToken)
		})
	}
}

func TestServiceVerifier_AcceptsBothKeysDuringRotation(t *testing.T) {
	t.Parallel()
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier, err := jwt.NewServiceVerifier(config.AdminM2MConfig{
		Issuer:      testIssuer,
		Audience:    testAudience,
		MaxTokenTTL: 15 * time.Minute,
		PublicKeys: []config.AdminM2MPublicKey{
			{KID: testKID, PEM: publicKeyPEM(t, oldKey)},
			{KID: "kid-2", PEM: publicKeyPEM(t, newKey)},
		},
	})
	require.NoError(t, err)

	_, err = verifier.Verify(signRS256(t, oldKey, validClaims()))
	require.NoError(t, err)

	rotated := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, validClaims())
	rotated.Header["kid"] = "kid-2"
	signed, err := rotated.SignedString(newKey)
	require.NoError(t, err)

	_, err = verifier.Verify(signed)
	require.NoError(t, err)
}

func TestServiceVerifier_AcceptsSingleLinePublicKeys(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rawPEM := publicKeyPEM(t, key)

	tests := []struct {
		name string
		pem  string
	}{
		{name: "base64", pem: base64.StdEncoding.EncodeToString([]byte(rawPEM))},
		{name: "escaped newlines", pem: strings.ReplaceAll(rawPEM, "\n", "\\n")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := jwt.NewServiceVerifier(config.AdminM2MConfig{
				Issuer:      testIssuer,
				Audience:    testAudience,
				MaxTokenTTL: 15 * time.Minute,
				PublicKeys:  []config.AdminM2MPublicKey{{KID: testKID, PEM: tc.pem}},
			})
			require.NoError(t, err)

			_, err = verifier.Verify(signRS256(t, key, validClaims()))
			require.NoError(t, err)
		})
	}
}

func TestServiceVerifier_KeylessEntryVerifiesAnyKid(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier, err := jwt.NewServiceVerifier(config.AdminM2MConfig{
		Issuer:      testIssuer,
		Audience:    testAudience,
		MaxTokenTTL: 15 * time.Minute,
		PublicKeys:  []config.AdminM2MPublicKey{{PEM: publicKeyPEM(t, key)}},
	})
	require.NoError(t, err)

	_, err = verifier.Verify(signRS256(t, key, validClaims()))
	require.NoError(t, err)

	unlabelled := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, validClaims())
	signed, err := unlabelled.SignedString(key)
	require.NoError(t, err)
	_, err = verifier.Verify(signed)
	require.NoError(t, err)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = verifier.Verify(signRS256(t, other, validClaims()))
	require.ErrorIs(t, err, jwt.ErrInvalidServiceToken)
}

func TestServiceVerifier_DisabledWithoutKeys(t *testing.T) {
	t.Parallel()
	verifier, err := jwt.NewServiceVerifier(config.AdminM2MConfig{Issuer: testIssuer, Audience: testAudience})
	require.NoError(t, err)
	require.False(t, verifier.Enabled())

	_, err = verifier.Verify("any.token.value")
	require.ErrorIs(t, err, jwt.ErrServiceTokensDisabled)
}

func TestServiceVerifier_RejectsUnparsableKeyAtBoot(t *testing.T) {
	t.Parallel()
	_, err := jwt.NewServiceVerifier(config.AdminM2MConfig{
		Issuer:     testIssuer,
		Audience:   testAudience,
		PublicKeys: []config.AdminM2MPublicKey{{KID: testKID, PEM: "not-a-pem"}},
	})
	require.Error(t, err)
}
