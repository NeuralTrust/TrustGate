package sts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner("https://gw.example.com", "", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// publicKeyFromJWKS reconstructs the RSA key from the published JWKS, proving
// downstreams can verify minted tokens with the discovery document alone.
func publicKeyFromJWKS(t *testing.T, s *Signer) *rsa.PublicKey {
	t.Helper()
	keys := s.JWKS()["keys"].([]map[string]any)
	if len(keys) != 1 {
		t.Fatalf("JWKS keys = %d, want 1", len(keys))
	}
	nb, err := base64.RawURLEncoding.DecodeString(keys[0]["n"].(string))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(keys[0]["e"].(string))
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
}

func TestSigner_MintAndVerifyAgainstJWKS(t *testing.T) {
	t.Parallel()
	s := newTestSigner(t)
	signed, err := s.MintClaims(jwt.MapClaims{"sub": "alice", "aud": "https://up.example.com"}, time.Minute)
	if err != nil {
		t.Fatalf("MintClaims: %v", err)
	}
	pub := publicKeyFromJWKS(t, s)
	parsed, err := jwt.Parse(signed, func(tok *jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("verify minted token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://gw.example.com" {
		t.Fatalf("iss = %v, want gateway issuer", claims["iss"])
	}
	if claims["sub"] != "alice" {
		t.Fatalf("sub = %v, want alice", claims["sub"])
	}
	if claims["jti"] == nil || claims["exp"] == nil {
		t.Fatal("jti/exp not stamped")
	}
}

func TestNewSigner_ParsesPKCS8PEM(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	s, err := NewSigner("iss", pemKey, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewSigner with PKCS8 PEM: %v", err)
	}
	if s.Issuer() != "iss" {
		t.Fatalf("Issuer = %q", s.Issuer())
	}
}

// Multi-line PEM cannot live in .env files; the signer accepts the two
// env-safe encodings: base64-wrapped PEM and literal \n escapes.
func TestNewSigner_AcceptsEnvSafeKeyEncodings(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	t.Run("base64-wrapped PEM", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString([]byte(pemKey))
		if _, err := NewSigner("iss", encoded, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("NewSigner with base64 PEM: %v", err)
		}
	})

	t.Run("literal backslash-n escapes", func(t *testing.T) {
		t.Parallel()
		escaped := strings.ReplaceAll(pemKey, "\n", `\n`)
		if _, err := NewSigner("iss", escaped, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("NewSigner with \\n-escaped PEM: %v", err)
		}
	})
}

func TestNewSigner_RejectsGarbagePEM(t *testing.T) {
	t.Parallel()
	if _, err := NewSigner("iss", "not pem", slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("NewSigner accepted garbage PEM")
	}
}
