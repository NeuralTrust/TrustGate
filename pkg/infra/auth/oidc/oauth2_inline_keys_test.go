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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestOAuth2Verifier_VerifiesTokenSignedByInlinePublicKey(t *testing.T) {
	t.Parallel()
	key := newRSAKey(t)
	token := signToken(t, key, "", jwt.MapClaims{
		"iss": "urn:example:idp",
		"aud": []string{"gateway"},
		"oid": "entra-object-id",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	verifier := appauth.NewOAuth2Verifier(NewVerifierWithCache(NewJWKSCache(nil, time.Minute)))
	got, err := verifier.Verify(context.Background(), token, domain.OAuth2Config{
		Issuer:       "urn:example:idp",
		Audiences:    []string{"gateway"},
		PublicKeys:   []string{publicKeyPEM(t, &key.PublicKey)},
		Algorithms:   []string{"RS256"},
		SubjectClaim: "oid",
	})
	requireNoError(t, err)
	if got.Subject != "entra-object-id" {
		t.Fatalf("Subject = %q, want entra-object-id", got.Subject)
	}
}

func TestOAuth2Verifier_InlinePublicKeysStayCandidatesAlongsideJWKS(t *testing.T) {
	t.Parallel()
	inlineKey := newRSAKey(t)
	jwksKey := newRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requireNoError(t, json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("kid-1", &jwksKey.PublicKey)}}))
	}))
	t.Cleanup(server.Close)

	token := signToken(t, inlineKey, "", jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": []string{"gateway"},
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	verifier := appauth.NewOAuth2Verifier(NewVerifierWithCache(NewJWKSCache(server.Client(), time.Minute)))
	got, err := verifier.Verify(context.Background(), token, domain.OAuth2Config{
		Issuer:     "https://issuer.example.com",
		Audiences:  []string{"gateway"},
		JWKSURL:    server.URL,
		PublicKeys: []string{publicKeyPEM(t, &inlineKey.PublicKey)},
	})
	requireNoError(t, err)
	if got.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", got.Subject)
	}
}
