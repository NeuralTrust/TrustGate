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

package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/oidc"
	"github.com/golang-jwt/jwt/v5"
)

type oidcStub struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
	server *httptest.Server
}

func newOIDCStub(t *testing.T) *oidcStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s := &oidcStub{key: key, kid: "kid-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": s.kid,
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": s.server.URL + "/jwks"})
	})
	s.server = httptest.NewServer(mux)
	s.issuer = s.server.URL
	t.Cleanup(s.server.Close)
	return s
}

func (s *oidcStub) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	raw, err := token.SignedString(s.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func (s *oidcStub) baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": s.issuer,
		"sub": "user-1",
		"aud": "trustgate",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"scp": "mcp.read mcp.call",
	}
}

func (s *oidcStub) config() *authdomain.OAuth2Config {
	return &authdomain.OAuth2Config{
		Issuer:    s.issuer,
		JWKSURL:   s.server.URL + "/jwks",
		Audiences: []string{"trustgate"},
	}
}

func newValidator() *oidc.OAuth2TokenValidator {
	return oidc.NewOAuth2TokenValidator(oidc.NewVerifier(), nil)
}

func TestOAuth2TokenValidator_ValidToken(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()

	principal, err := v.Validate(context.Background(), stub.sign(t, stub.baseClaims()), stub.config())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.Subject != "user-1" {
		t.Fatalf("subject = %q", principal.Subject)
	}
	if len(principal.Scopes) != 2 {
		t.Fatalf("scopes = %v", principal.Scopes)
	}
	if principal.RawToken == "" {
		t.Fatal("raw token must be retained for downstream exchange")
	}
}

func TestOAuth2TokenValidator_DiscoversJWKSWhenURLNotConfigured(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	cfg := stub.config()
	cfg.JWKSURL = ""

	if _, err := v.Validate(context.Background(), stub.sign(t, stub.baseClaims()), cfg); err != nil {
		t.Fatalf("validate via discovery: %v", err)
	}
}

func TestOAuth2TokenValidator_RejectsWrongIssuer(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	claims := stub.baseClaims()
	claims["iss"] = "https://evil.example.com"

	if _, err := v.Validate(context.Background(), stub.sign(t, claims), stub.config()); err == nil {
		t.Fatal("expected issuer rejection")
	}
}

func TestOAuth2TokenValidator_RejectsWrongAudience(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	claims := stub.baseClaims()
	claims["aud"] = "someone-else"

	if _, err := v.Validate(context.Background(), stub.sign(t, claims), stub.config()); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func TestOAuth2TokenValidator_RejectsExpiredToken(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	claims := stub.baseClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	if _, err := v.Validate(context.Background(), stub.sign(t, claims), stub.config()); err == nil {
		t.Fatal("expected expiry rejection")
	}
}

func TestOAuth2TokenValidator_RejectsMissingRequiredScopes(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	cfg := stub.config()
	cfg.RequiredScopes = []string{"mcp.admin"}

	if _, err := v.Validate(context.Background(), stub.sign(t, stub.baseClaims()), cfg); err == nil {
		t.Fatal("expected scope rejection")
	}
}

func TestOAuth2TokenValidator_AcceptsScopesFromPermissionsClaim(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	cfg := stub.config()
	cfg.RequiredScopes = []string{"mcp.admin"}
	claims := stub.baseClaims()
	claims["permissions"] = []any{"mcp.admin"}

	principal, err := v.Validate(context.Background(), stub.sign(t, claims), cfg)
	if err != nil {
		t.Fatalf("permissions claim must satisfy required scopes: %v", err)
	}
	if !principal.HasScopes([]string{"mcp.admin"}) {
		t.Fatal("permissions claim must be merged into scopes")
	}
}

func TestOAuth2TokenValidator_AudienceResourceURIEquivalence(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()

	cfg := stub.config()
	cfg.Audiences = []string{"api://client-guid"}
	claims := stub.baseClaims()
	claims["aud"] = "client-guid"
	if _, err := v.Validate(context.Background(), stub.sign(t, claims), cfg); err != nil {
		t.Fatalf("bare-guid aud must satisfy api:// audience config: %v", err)
	}

	cfg.Audiences = []string{"client-guid"}
	claims["aud"] = "api://client-guid"
	if _, err := v.Validate(context.Background(), stub.sign(t, claims), cfg); err != nil {
		t.Fatalf("api:// aud must satisfy bare-guid audience config: %v", err)
	}

	cfg.Audiences = []string{"api://other"}
	if _, err := v.Validate(context.Background(), stub.sign(t, claims), cfg); err == nil {
		t.Fatal("expected audience rejection for unrelated resource")
	}
}

func TestOAuth2TokenValidator_RejectsUnsignedToken(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, stub.baseClaims())
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	if _, err := v.Validate(context.Background(), raw, stub.config()); err == nil {
		t.Fatal("expected alg=none rejection")
	}
}

func TestOAuth2TokenValidator_EntraStyleOIDSubject(t *testing.T) {
	stub := newOIDCStub(t)
	v := newValidator()
	claims := stub.baseClaims()
	claims["oid"] = "object-id-42"

	principal, err := v.Validate(context.Background(), stub.sign(t, claims), stub.config())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.Subject != "object-id-42" {
		t.Fatalf("subject should prefer oid, got %q", principal.Subject)
	}
}
