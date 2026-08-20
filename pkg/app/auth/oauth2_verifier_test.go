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

package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/stretchr/testify/mock"
)

const verifierToken = "header.payload.signature"

func TestOAuth2Verifier_ForwardsConfigUnchanged(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  domain.OAuth2Config
	}{
		{
			name: "a jwks url config keeps its scopes, algorithms and subject claim",
			cfg: domain.OAuth2Config{
				Issuer:         "https://issuer.example.com",
				Audiences:      []string{"gateway"},
				JWKSURL:        "https://issuer.example.com/jwks",
				RequiredScopes: []string{"chat"},
				Algorithms:     []string{"RS256"},
				SubjectClaim:   "oid",
			},
		},
		{
			name: "inline public keys reach the verifier without a jwks url",
			cfg: domain.OAuth2Config{
				Issuer:     "urn:example:idp",
				Audiences:  []string{"gateway"},
				PublicKeys: []string{"-----BEGIN PUBLIC KEY-----"},
			},
		},
		{
			name: "inline public keys and a jwks url are both forwarded",
			cfg: domain.OAuth2Config{
				Issuer:     "https://issuer.example.com",
				Audiences:  []string{"gateway"},
				JWKSURL:    "https://issuer.example.com/jwks",
				PublicKeys: []string{"-----BEGIN PUBLIC KEY-----"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			claims := &appauth.VerifiedClaims{Subject: "user-1"}
			jwtVerifier := authmocks.NewJWTVerifier(t)
			jwtVerifier.EXPECT().
				Verify(mock.Anything, verifierToken, tt.cfg).
				Return(claims, nil).
				Once()

			got, err := appauth.NewOAuth2Verifier(jwtVerifier).
				Verify(context.Background(), verifierToken, tt.cfg)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != claims {
				t.Fatalf("Verify claims = %+v, want %+v", got, claims)
			}
		})
	}
}

func TestOAuth2Verifier_RejectsConfigsWithoutUsableKeyMaterial(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  domain.OAuth2Config
	}{
		{
			name: "introspection only",
			cfg: domain.OAuth2Config{
				Issuer:           "urn:example:idp",
				Audiences:        []string{"gateway"},
				IntrospectionURL: "https://issuer.example.com/introspect",
			},
		},
		{
			name: "blank public keys are not key material",
			cfg: domain.OAuth2Config{
				Issuer:     "urn:example:idp",
				Audiences:  []string{"gateway"},
				PublicKeys: []string{"", "   ", "\n\t"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jwtVerifier := authmocks.NewJWTVerifier(t)

			got, err := appauth.NewOAuth2Verifier(jwtVerifier).Verify(
				context.Background(),
				verifierToken,
				tt.cfg,
			)
			if !errors.Is(err, appauth.ErrInvalidAuthRequest) {
				t.Fatalf("Verify error = %v, want ErrInvalidAuthRequest", err)
			}
			if got != nil {
				t.Fatalf("Verify claims = %+v, want nil", got)
			}
		})
	}
}
