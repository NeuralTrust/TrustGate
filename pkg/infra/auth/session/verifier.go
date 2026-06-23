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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appsts "github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/golang-jwt/jwt/v5"
)

var _ appauth.SessionTokenVerifier = (*Verifier)(nil)

type Verifier struct {
	issuer    string
	publicKey *rsa.PublicKey
	kid       string
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyID   string `json:"kid"`
	KeyType string `json:"kty"`
	N       string `json:"n"`
	E       string `json:"e"`
}

func NewVerifier(signer appsts.TokenSigner) (*Verifier, error) {
	if signer == nil {
		return nil, fmt.Errorf("session verifier: nil signer")
	}
	rawJWKS, err := json.Marshal(signer.JWKS())
	if err != nil {
		return nil, fmt.Errorf("session verifier: marshal jwks: %w", err)
	}
	var set jwkSet
	if err := json.Unmarshal(rawJWKS, &set); err != nil {
		return nil, fmt.Errorf("session verifier: decode jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("session verifier: jwks has no keys")
	}
	key := set.Keys[0]
	if key.KeyType != "RSA" {
		return nil, fmt.Errorf("session verifier: unsupported kty %q", key.KeyType)
	}
	if key.KeyID == "" {
		return nil, fmt.Errorf("session verifier: jwks key has no kid")
	}
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("session verifier: decode n: %w", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("session verifier: decode e: %w", err)
	}
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, fmt.Errorf("session verifier: empty exponent")
	}
	return &Verifier{
		issuer:    signer.Issuer(),
		publicKey: &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent},
		kid:       key.KeyID,
	}, nil
}

func (v *Verifier) Issuer() string { return v.issuer }

func (v *Verifier) Verify(_ context.Context, raw string) (*identity.Principal, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if _, err := parser.ParseWithClaims(raw, claims, v.keyfunc); err != nil {
		return nil, fmt.Errorf("session verifier: %w", err)
	}
	subject, _ := claims["sub"].(string)
	var scopes []string
	if scope, ok := claims["scope"].(string); ok && scope != "" {
		scopes = strings.Fields(scope)
	}
	return &identity.Principal{
		Subject:  subject,
		Method:   identity.MethodJWT,
		Issuer:   v.issuer,
		Claims:   map[string]any(claims),
		Scopes:   scopes,
		RawToken: raw,
	}, nil
}

func (v *Verifier) keyfunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if kid != v.kid {
		return nil, fmt.Errorf("unexpected kid %q", kid)
	}
	return v.publicKey, nil
}
