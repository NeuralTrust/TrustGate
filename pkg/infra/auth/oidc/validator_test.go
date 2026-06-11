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

type idpStub struct {
	key    *rsa.PrivateKey
	kid    string
	issuer string
	server *httptest.Server
}

func newIDPStub(t *testing.T) *idpStub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s := &idpStub{key: key, kid: "kid-1"}
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

func (s *idpStub) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	raw, err := token.SignedString(s.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func (s *idpStub) baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": s.issuer,
		"sub": "user-1",
		"aud": "trustgate",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"scp": "mcp.read mcp.call",
	}
}

func (s *idpStub) config() *authdomain.OAuth2Config {
	return &authdomain.OAuth2Config{
		Issuer:    s.issuer,
		JWKSURL:   s.server.URL + "/jwks",
		Audiences: []string{"trustgate"},
	}
}

func TestValidator_ValidToken(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)

	principal, err := v.Validate(context.Background(), idp.sign(t, idp.baseClaims()), idp.config())
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

func TestValidator_DiscoversJWKSWhenURLNotConfigured(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	cfg := idp.config()
	cfg.JWKSURL = ""

	if _, err := v.Validate(context.Background(), idp.sign(t, idp.baseClaims()), cfg); err != nil {
		t.Fatalf("validate via discovery: %v", err)
	}
}

func TestValidator_RejectsWrongIssuer(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	claims := idp.baseClaims()
	claims["iss"] = "https://evil.example.com"

	if _, err := v.Validate(context.Background(), idp.sign(t, claims), idp.config()); err == nil {
		t.Fatal("expected issuer rejection")
	}
}

func TestValidator_RejectsWrongAudience(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	claims := idp.baseClaims()
	claims["aud"] = "someone-else"

	if _, err := v.Validate(context.Background(), idp.sign(t, claims), idp.config()); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func TestValidator_RejectsExpiredToken(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	claims := idp.baseClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	if _, err := v.Validate(context.Background(), idp.sign(t, claims), idp.config()); err == nil {
		t.Fatal("expected expiry rejection")
	}
}

func TestValidator_RejectsMissingRequiredScopes(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	cfg := idp.config()
	cfg.RequiredScopes = []string{"mcp.admin"}

	if _, err := v.Validate(context.Background(), idp.sign(t, idp.baseClaims()), cfg); err == nil {
		t.Fatal("expected scope rejection")
	}
}

func TestValidator_AudienceResourceURIEquivalence(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)

	// Entra v2.0: token aud is the bare client id, config uses the api:// URI.
	cfg := idp.config()
	cfg.Audiences = []string{"api://client-guid"}
	claims := idp.baseClaims()
	claims["aud"] = "client-guid"
	if _, err := v.Validate(context.Background(), idp.sign(t, claims), cfg); err != nil {
		t.Fatalf("bare-guid aud must satisfy api:// audience config: %v", err)
	}

	// Entra v1.0: token aud is the api:// URI, config uses the bare client id.
	cfg.Audiences = []string{"client-guid"}
	claims["aud"] = "api://client-guid"
	if _, err := v.Validate(context.Background(), idp.sign(t, claims), cfg); err != nil {
		t.Fatalf("api:// aud must satisfy bare-guid audience config: %v", err)
	}

	cfg.Audiences = []string{"api://other"}
	if _, err := v.Validate(context.Background(), idp.sign(t, claims), cfg); err == nil {
		t.Fatal("expected audience rejection for unrelated resource")
	}
}

func TestValidator_RejectsUnsignedToken(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	token := jwt.NewWithClaims(jwt.SigningMethodNone, idp.baseClaims())
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	if _, err := v.Validate(context.Background(), raw, idp.config()); err == nil {
		t.Fatal("expected alg=none rejection")
	}
}

func TestValidator_EntraStyleOIDSubject(t *testing.T) {
	idp := newIDPStub(t)
	v := oidc.NewValidator(nil)
	claims := idp.baseClaims()
	claims["oid"] = "object-id-42"

	principal, err := v.Validate(context.Background(), idp.sign(t, claims), idp.config())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.Subject != "object-id-42" {
		t.Fatalf("subject should prefer oid, got %q", principal.Subject)
	}
}
