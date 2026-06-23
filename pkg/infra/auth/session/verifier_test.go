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

package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"

	appsts "github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	stssigner "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://gateway.example/sts"

func TestVerify_Success(t *testing.T) {
	t.Parallel()
	signer, err := stssigner.NewSigner(testIssuer, "", nil)
	require.NoError(t, err)

	raw, err := signer.MintClaims(jwt.MapClaims{
		"sub":       "user-123",
		"scope":     "read write admin",
		"token_use": "mcp_session",
		"authid":    "auth-1",
	}, time.Hour)
	require.NoError(t, err)

	verifier, err := NewVerifier(signer)
	require.NoError(t, err)

	principal, err := verifier.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user-123", principal.Subject)
	assert.Equal(t, identity.MethodJWT, principal.Method)
	assert.Equal(t, signer.Issuer(), principal.Issuer)
	assert.Equal(t, []string{"read", "write", "admin"}, principal.Scopes)
	assert.Equal(t, raw, principal.RawToken)
	assert.Equal(t, "mcp_session", principal.Claims["token_use"])
}

func TestVerify_NoScopeClaim(t *testing.T) {
	t.Parallel()
	signer, err := stssigner.NewSigner(testIssuer, "", nil)
	require.NoError(t, err)

	raw, err := signer.MintClaims(jwt.MapClaims{"sub": "user-9"}, time.Hour)
	require.NoError(t, err)

	verifier, err := NewVerifier(signer)
	require.NoError(t, err)

	principal, err := verifier.Verify(context.Background(), raw)
	require.NoError(t, err)
	assert.Empty(t, principal.Scopes)
}

func TestVerifier_Issuer(t *testing.T) {
	t.Parallel()
	signer, err := stssigner.NewSigner(testIssuer, "", nil)
	require.NoError(t, err)

	verifier, err := NewVerifier(signer)
	require.NoError(t, err)
	assert.Equal(t, testIssuer, verifier.Issuer())
}

func TestVerify_WrongKid(t *testing.T) {
	t.Parallel()
	signer, err := stssigner.NewSigner(testIssuer, "", nil)
	require.NoError(t, err)
	otherSigner, err := stssigner.NewSigner(testIssuer, "", nil)
	require.NoError(t, err)

	raw, err := otherSigner.MintClaims(jwt.MapClaims{"sub": "user-123"}, time.Hour)
	require.NoError(t, err)

	verifier, err := NewVerifier(signer)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_Expired(t *testing.T) {
	t.Parallel()
	key, kid := newTestKey(t)
	verifier, err := NewVerifier(&stubSigner{issuer: testIssuer, key: key, kid: kid})
	require.NoError(t, err)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"sub": "user-123",
		"iss": testIssuer,
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	_, err = verifier.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_WrongIssuer(t *testing.T) {
	t.Parallel()
	key, kid := newTestKey(t)
	verifier, err := NewVerifier(&stubSigner{issuer: testIssuer, key: key, kid: kid})
	require.NoError(t, err)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"sub": "user-123",
		"iss": "https://evil.example/sts",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = verifier.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_AlgNone(t *testing.T) {
	t.Parallel()
	key, kid := newTestKey(t)
	verifier, err := NewVerifier(&stubSigner{issuer: testIssuer, key: key, kid: kid})
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "user-123",
		"iss": testIssuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = kid
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), raw)
	require.Error(t, err)
}

func TestVerify_TamperedSignature(t *testing.T) {
	t.Parallel()
	key, kid := newTestKey(t)
	verifier, err := NewVerifier(&stubSigner{issuer: testIssuer, key: key, kid: kid})
	require.NoError(t, err)

	raw := signToken(t, key, kid, jwt.MapClaims{
		"sub": "user-123",
		"iss": testIssuer,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tampered := raw[:len(raw)-2] + flipLast(raw)

	_, err = verifier.Verify(context.Background(), tampered)
	require.Error(t, err)
}

func TestVerifier_NoHTTPClientField(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(Verifier{})
	httpClientType := reflect.TypeOf(&http.Client{})
	for i := 0; i < typ.NumField(); i++ {
		assert.NotEqual(t, httpClientType, typ.Field(i).Type,
			"Verifier must not embed an *http.Client (AC#4)")
	}
}

func newTestKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key, "test-kid"
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	require.NoError(t, err)
	return raw
}

func flipLast(raw string) string {
	last := raw[len(raw)-1]
	if last == 'A' {
		return "BB"
	}
	return "AA"
}

var _ appsts.TokenSigner = (*stubSigner)(nil)

type stubSigner struct {
	issuer string
	key    *rsa.PrivateKey
	kid    string
}

func (s *stubSigner) Issuer() string { return s.issuer }

func (s *stubSigner) MintClaims(claims jwt.MapClaims, _ time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	return token.SignedString(s.key)
}

func (s *stubSigner) JWKS() map[string]any {
	pub := &s.key.PublicKey
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": s.kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
}
