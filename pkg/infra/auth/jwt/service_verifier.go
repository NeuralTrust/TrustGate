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

package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

// TokenUseAdminM2M marks a machine-to-machine admin credential. Tokens without
// this marker are never accepted by the service verifier, so a token minted for
// another plane cannot be replayed against the admin API.
const TokenUseAdminM2M = "admin_m2m"

var (
	// ErrServiceTokensDisabled is returned when no verification key, issuer or
	// audience is configured, which makes every service token unverifiable.
	ErrServiceTokensDisabled = errors.New("service tokens are not configured")
	// ErrInvalidServiceToken covers every rejection reason. The cause is logged
	// by the caller; the wire response stays generic on purpose.
	ErrInvalidServiceToken = errors.New("invalid service token")
)

// ServiceClaims is the machine-to-machine admin credential contract. Every
// field is required: a token that omits the gateway binding or the scopes would
// otherwise widen to the whole tenant.
type ServiceClaims struct {
	TokenUse  string   `json:"token_use"`
	TenantID  string   `json:"tenant_id"`
	GatewayID string   `json:"gateway_id"`
	Scopes    []string `json:"scopes"`
	jwt.RegisteredClaims
}

//go:generate mockery --name=ServiceVerifier --dir=. --output=./mocks --filename=service_verifier_mock.go --case=underscore --with-expecter
type ServiceVerifier interface {
	Enabled() bool
	Verify(tokenString string) (*ServiceClaims, error)
}

type serviceVerifier struct {
	issuer      string
	audience    string
	maxTokenTTL time.Duration
	keys        map[string]*rsa.PublicKey
}

// normalizePublicKeyPEM accepts raw PEM, `\n`-escaped PEM, or base64-encoded
// PEM. Base64 is what a config store can hold on a single line without quoting
// or escaping games, and matches how the control plane provisions its half.
func normalizePublicKeyPEM(raw string) []byte {
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, "-----BEGIN") {
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return []byte(trimmed)
		}
		return decoded
	}
	return []byte(strings.ReplaceAll(trimmed, "\\n", "\n"))
}

// NewServiceVerifier builds the verifier from the configured public keys. A key
// that cannot be parsed fails boot instead of silently shrinking the trusted key
// set, which would surface later as unexplained rejections mid-rotation.
func NewServiceVerifier(cfg config.AdminM2MConfig) (ServiceVerifier, error) {
	keys := make(map[string]*rsa.PublicKey, len(cfg.PublicKeys))
	for _, entry := range cfg.PublicKeys {
		key, err := jwt.ParseRSAPublicKeyFromPEM(normalizePublicKeyPEM(entry.PEM))
		if err != nil {
			return nil, fmt.Errorf("parse admin m2m public key %q: %w", entry.KID, err)
		}
		keys[entry.KID] = key
	}
	return &serviceVerifier{
		issuer:      cfg.Issuer,
		audience:    cfg.Audience,
		maxTokenTTL: cfg.MaxTokenTTL,
		keys:        keys,
	}, nil
}

func (v *serviceVerifier) Enabled() bool {
	return v.issuer != "" && v.audience != "" && len(v.keys) > 0
}

// Verify authenticates a service token. Signing keys are asymmetric and pinned
// by `kid`, the algorithm family is restricted to RS256 so a token cannot be
// downgraded to HMAC against a public key, and every business claim required to
// authorize the request must be present.
func (v *serviceVerifier) Verify(tokenString string) (*ServiceClaims, error) {
	if !v.Enabled() {
		return nil, ErrServiceTokensDisabled
	}

	claims := &ServiceClaims{}
	_, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		v.keyForToken,
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidServiceToken, err.Error())
	}

	if err := v.validateClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *serviceVerifier) keyForToken(token *jwt.Token) (interface{}, error) {
	kid, _ := token.Header["kid"].(string)
	if kid != "" {
		if key, ok := v.keys[kid]; ok {
			return key, nil
		}
	}
	// A key configured without a kid is the only trusted key, so there is
	// nothing to select between and the header hint is irrelevant. Rotation is
	// what makes kids necessary, and that path configures them explicitly.
	if key, ok := v.keys[""]; ok {
		return key, nil
	}
	if kid == "" {
		return nil, errors.New("token header is missing kid")
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

func (v *serviceVerifier) validateClaims(claims *ServiceClaims) error {
	if claims.TokenUse != TokenUseAdminM2M {
		return fmt.Errorf("%w: token_use must be %q", ErrInvalidServiceToken, TokenUseAdminM2M)
	}
	if strings.TrimSpace(claims.TenantID) == "" {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidServiceToken)
	}
	if strings.TrimSpace(claims.GatewayID) == "" {
		return fmt.Errorf("%w: gateway_id is required", ErrInvalidServiceToken)
	}
	if len(claims.Scopes) == 0 {
		return fmt.Errorf("%w: scopes are required", ErrInvalidServiceToken)
	}
	return v.validateLifetime(claims)
}

func (v *serviceVerifier) validateLifetime(claims *ServiceClaims) error {
	if v.maxTokenTTL <= 0 {
		return nil
	}
	if claims.IssuedAt == nil {
		return fmt.Errorf("%w: iat is required", ErrInvalidServiceToken)
	}
	if lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time); lifetime > v.maxTokenTTL {
		return fmt.Errorf("%w: lifetime %s exceeds the %s ceiling", ErrInvalidServiceToken, lifetime, v.maxTokenTTL)
	}
	return nil
}
