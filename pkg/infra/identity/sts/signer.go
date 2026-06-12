// Package sts implements the app STS ports: RSA JWT signing/JWKS publication
// and the IdP token-grant client (OIDC-discovered endpoints).
package sts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	appsts "github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	"github.com/golang-jwt/jwt/v5"
)

var _ appsts.TokenSigner = (*Signer)(nil)

// Signer mints TrustGate-issued JWTs and publishes the verification JWKS.
type Signer struct {
	issuer string
	key    *rsa.PrivateKey
	kid    string
}

// NewSigner loads the RSA signing key from PEM, or generates an ephemeral
// key when none is configured (development only: minted tokens do not
// survive restarts and replicas would not share a key).
func NewSigner(issuer, keyPEM string, logger *slog.Logger) (*Signer, error) {
	if issuer == "" {
		issuer = "trustgate"
	}
	var key *rsa.PrivateKey
	if keyPEM != "" {
		parsed, err := parseRSAPrivateKey(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("sts: parse signing key: %w", err)
		}
		key = parsed
	} else {
		generated, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("sts: generate ephemeral key: %w", err)
		}
		key = generated
		if logger != nil {
			logger.Warn("sts: no STS_SIGNING_KEY configured; using an ephemeral key (dev only, not shared across replicas)")
		}
	}
	return &Signer{issuer: issuer, key: key, kid: keyID(&key.PublicKey)}, nil
}

func (s *Signer) Issuer() string { return s.issuer }

// MintClaims signs the claims (RS256), stamping iss/iat/exp/jti.
func (s *Signer) MintClaims(claims jwt.MapClaims, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = appsts.DefaultTokenTTL
	}
	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("sts: %w", err)
	}
	now := time.Now()
	claims["iss"] = s.issuer
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()
	claims["jti"] = jti
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("sts: sign: %w", err)
	}
	return signed, nil
}

// JWKS is the published verification document for downstreams.
func (s *Signer) JWKS() map[string]any {
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

// parseRSAPrivateKey accepts the key as raw PEM, as PEM with literal \n
// escapes, or base64-wrapped PEM - the latter two are how multi-line keys
// survive .env files and docker-compose environment blocks.
func parseRSAPrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	keyPEM = strings.TrimSpace(keyPEM)
	if !strings.Contains(keyPEM, "-----BEGIN") {
		decoded, err := base64.StdEncoding.DecodeString(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("no PEM block found (provide PEM, \\n-escaped PEM, or base64-encoded PEM)")
		}
		keyPEM = string(decoded)
	}
	keyPEM = strings.ReplaceAll(keyPEM, `\n`, "\n")
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key")
	}
	return key, nil
}

func keyID(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func randomJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("jti entropy unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
