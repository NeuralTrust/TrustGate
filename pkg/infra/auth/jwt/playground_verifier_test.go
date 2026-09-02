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
	"encoding/pem"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const playgroundHSSecret = "server-secret-0123456789abcdef0123456789"

func generateKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return key, string(pemBytes)
}

func mintRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func playgroundClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"purpose":       "playground",
		"consumer_slug": "my-consumer",
		"aud":           infrajwt.AudiencePlayground,
		"iat":           now.Unix(),
		"exp":           now.Add(5 * time.Minute).Unix(),
	}
}

func mintHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

func staticSource(t *testing.T, entries ...config.AdminM2MPublicKey) infrajwt.PlaygroundKeySource {
	t.Helper()
	source, err := infrajwt.StaticPlaygroundKeys(entries)
	require.NoError(t, err)
	return source
}

func TestPlaygroundVerifier_HS256WithServerSecret(t *testing.T) {
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: playgroundHSSecret}, nil)

	claims, err := v.Verify(mintHS256(t, playgroundHSSecret, playgroundClaims()))
	require.NoError(t, err)
	assert.Equal(t, "playground", claims.Purpose)
	assert.Equal(t, "my-consumer", claims.ConsumerSlug)
}

func TestPlaygroundVerifier_HS256WrongSecretRejected(t *testing.T) {
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: playgroundHSSecret}, nil)

	_, err := v.Verify(mintHS256(t, "another-secret-another-secret-another", playgroundClaims()))
	assert.Error(t, err)
}

func TestPlaygroundVerifier_RS256WithIssuerKey(t *testing.T) {
	key, pubPEM := generateKeyPair(t)
	source := staticSource(t, config.AdminM2MPublicKey{KID: "2026-09", PEM: pubPEM})
	// No HS secret configured at all: the asymmetric path must stand alone.
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{}, source)

	claims, err := v.Verify(mintRS256(t, key, "2026-09", playgroundClaims()))
	require.NoError(t, err)
	assert.Equal(t, "playground", claims.Purpose)
	assert.Equal(t, "my-consumer", claims.ConsumerSlug)
}

func TestPlaygroundVerifier_RS256RequiresPlaygroundAudience(t *testing.T) {
	key, pubPEM := generateKeyPair(t)
	source := staticSource(t, config.AdminM2MPublicKey{KID: "2026-09", PEM: pubPEM})
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{}, source)

	// An admin M2M token signed by the same issuer must not be replayable
	// against the playground resolver: it carries the admin audience.
	claims := playgroundClaims()
	claims["aud"] = "trustgate-admin"
	_, err := v.Verify(mintRS256(t, key, "2026-09", claims))
	assert.Error(t, err)
}

func TestPlaygroundVerifier_RS256UnknownKidRejected(t *testing.T) {
	key, pubPEM := generateKeyPair(t)
	source := staticSource(t, config.AdminM2MPublicKey{KID: "2026-09", PEM: pubPEM})
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{}, source)

	_, err := v.Verify(mintRS256(t, key, "other-kid", playgroundClaims()))
	assert.Error(t, err)
}

func TestPlaygroundVerifier_RS256KidlessKeyServesAsDefault(t *testing.T) {
	key, pubPEM := generateKeyPair(t)
	source := staticSource(t, config.AdminM2MPublicKey{PEM: pubPEM})
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{}, source)

	_, err := v.Verify(mintRS256(t, key, "any-kid", playgroundClaims()))
	assert.NoError(t, err)
}

func TestPlaygroundVerifier_RS256WithoutKeysRejected(t *testing.T) {
	key, _ := generateKeyPair(t)
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: playgroundHSSecret}, nil)

	_, err := v.Verify(mintRS256(t, key, "2026-09", playgroundClaims()))
	assert.Error(t, err)
}

func TestPlaygroundVerifier_ExpiredTokenRejected(t *testing.T) {
	v := infrajwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: playgroundHSSecret}, nil)

	claims := playgroundClaims()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	_, err := v.Verify(mintHS256(t, playgroundHSSecret, claims))
	assert.Error(t, err)
}

func TestCombinePlaygroundKeys_MergesAndSkipsNil(t *testing.T) {
	_, pemA := generateKeyPair(t)
	_, pemB := generateKeyPair(t)
	a := staticSource(t, config.AdminM2MPublicKey{KID: "a", PEM: pemA})
	b := staticSource(t, config.AdminM2MPublicKey{KID: "b", PEM: pemB})

	merged := infrajwt.CombinePlaygroundKeys(a, nil, b).PlaygroundTokenKeys()
	assert.Len(t, merged, 2)
	assert.Contains(t, merged, "a")
	assert.Contains(t, merged, "b")
}

func TestStaticPlaygroundKeys_MalformedKeyFails(t *testing.T) {
	_, err := infrajwt.StaticPlaygroundKeys([]config.AdminM2MPublicKey{{KID: "bad", PEM: "not-a-key"}})
	assert.Error(t, err)
}
