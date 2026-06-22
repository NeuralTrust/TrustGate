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

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestVerifier_VerifyJWKSRS256(t *testing.T) {
	t.Parallel()
	key := newRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("kid-1", &key.PublicKey)}}))
	}))
	t.Cleanup(server.Close)

	token := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss":    "https://issuer.example.com",
		"aud":    []string{"gateway"},
		"sub":    "user-1",
		"scope":  "chat read",
		"groups": []string{"gateway-admin"},
		"exp":    time.Now().Add(time.Hour).Unix(),
		"nbf":    time.Now().Add(-time.Minute).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(server.Client(), time.Minute))
	got, err := verifier.Verify(context.Background(), token, domain.OIDCConfig{
		Issuer:            "https://issuer.example.com",
		Audiences:         []string{"gateway"},
		JWKSURL:           server.URL,
		RequiredScopes:    []string{"chat"},
		AllowedAlgorithms: []string{"RS256"},
	})
	requireNoError(t, err)
	if got.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", got.Subject)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("Scopes = %+v, want two scopes", got.Scopes)
	}
}

func TestVerifier_VerifySelectsMatchingKID(t *testing.T) {
	t.Parallel()
	wrongKey := newRSAKey(t)
	rightKey := newRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{
			rsaJWK("", &wrongKey.PublicKey),
			rsaJWK("kid-2", &rightKey.PublicKey),
		}}))
	}))
	t.Cleanup(server.Close)

	token := signToken(t, rightKey, "kid-2", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(server.Client(), time.Minute))
	got, err := verifier.Verify(context.Background(), token, domain.OIDCConfig{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"gateway"},
		JWKSURL:   server.URL,
	})
	requireNoError(t, err)
	if got.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", got.Subject)
	}
}

func TestVerifier_VerifyWithoutKIDTriesCompatibleKeys(t *testing.T) {
	t.Parallel()
	wrongKey := newRSAKey(t)
	rightKey := newRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{
			rsaJWK("kid-1", &wrongKey.PublicKey),
			rsaJWK("kid-2", &rightKey.PublicKey),
		}}))
	}))
	t.Cleanup(server.Close)

	token := signToken(t, rightKey, "", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(server.Client(), time.Minute))
	got, err := verifier.Verify(context.Background(), token, domain.OIDCConfig{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"gateway"},
		JWKSURL:   server.URL,
	})
	requireNoError(t, err)
	if got.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", got.Subject)
	}
}

func TestVerifier_VerifyRefreshesJWKSOnKIDMiss(t *testing.T) {
	t.Parallel()
	key := newRSAKey(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{}}))
			return
		}
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("rotated", &key.PublicKey)}}))
	}))
	t.Cleanup(server.Close)

	token := signToken(t, key, "rotated", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(server.Client(), time.Minute))
	_, err := verifier.Verify(context.Background(), token, domain.OIDCConfig{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"gateway"},
		JWKSURL:   server.URL,
	})
	requireNoError(t, err)
	if requests.Load() != 2 {
		t.Fatalf("JWKS requests = %d, want 2", requests.Load())
	}
}

func TestVerifier_VerifyRefreshesJWKSOnSignatureFailure(t *testing.T) {
	t.Parallel()
	oldKey := newRSAKey(t)
	newKey := newRSAKey(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("rotated", &oldKey.PublicKey)}}))
			return
		}
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("rotated", &newKey.PublicKey)}}))
	}))
	t.Cleanup(server.Close)

	token := signToken(t, newKey, "rotated", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(server.Client(), time.Minute))
	_, err := verifier.Verify(context.Background(), token, domain.OIDCConfig{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"gateway"},
		JWKSURL:   server.URL,
	})
	requireNoError(t, err)
	if requests.Load() != 2 {
		t.Fatalf("JWKS requests = %d, want 2", requests.Load())
	}
}

func TestVerifier_VerifyRejectsInvalidIssuer(t *testing.T) {
	t.Parallel()
	key := newRSAKey(t)
	token := signToken(t, key, "", jwt.MapClaims{
		"iss": "https://wrong.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(nil, time.Minute))
	_, err := verifier.Verify(context.Background(), token, domain.OIDCConfig{
		Issuer:            "https://issuer.example.com",
		Audiences:         []string{"gateway"},
		PublicKeys:        []string{publicKeyPEM(t, &key.PublicKey)},
		AllowedAlgorithms: []string{"RS256"},
	})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerifier_PeekExtractsHints(t *testing.T) {
	t.Parallel()
	key := newRSAKey(t)
	token := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	verifier := NewVerifierWithCache(NewJWKSCache(nil, time.Minute))
	hints, err := verifier.Peek(token)
	requireNoError(t, err)
	if hints.Issuer != "https://issuer.example.com" || hints.KeyID != "kid-1" || hints.Algorithm != "RS256" {
		t.Fatalf("unexpected hints: %+v", hints)
	}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	requireNoError(t, err)
	return key
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	requireNoError(t, err)
	return signed
}

func rsaJWK(kid string, key *rsa.PublicKey) jwk {
	return jwk{
		KeyID:     kid,
		KeyType:   "RSA",
		Algorithm: "RS256",
		N:         base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func publicKeyPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	requireNoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
