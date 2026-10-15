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
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

const clockSkewLeeway = 30 * time.Second

//go:generate mockery --name=Manager --dir=. --output=./mocks --filename=jwt_manager_mock.go --case=underscore --with-expecter
type Manager interface {
	CreateToken() (string, error)
	ValidateToken(tokenString string) error
	DecodeToken(tokenString string) (*Claims, error)
}

type manager struct {
	config *config.ServerConfig
}

func NewJwtManager(config *config.ServerConfig) Manager {
	return &manager{config: config}
}

// PurposePlayground marks tokens minted exclusively for the dashboard
// playground. Purpose-tagged tokens are rejected by the admin API and only
// honored by the proxy-plane playground identity resolver.
const PurposePlayground = "playground"

type Claims struct {
	TenantID  string `json:"tenant_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Purpose restricts where a token is accepted. Empty means a regular
	// admin token; "playground" tokens are only valid on the proxy plane.
	Purpose string `json:"purpose,omitempty"`
	// ConsumerSlug binds a playground token to a single consumer route.
	ConsumerSlug string `json:"consumer_slug,omitempty"`
	// GatewayID binds a diagnostics token to a single gateway, so a leaked
	// token cannot probe anything beyond it.
	GatewayID string `json:"gateway_id,omitempty"`
	// TokenUse marks machine-to-machine credentials. Those are verified against
	// the asymmetric issuer key, so seeing it on a shared-secret token means the
	// token is being replayed on the wrong verifier and must be rejected.
	TokenUse string `json:"token_use,omitempty"`
	// PlatformAdmin is the explicit cross-tenant grant. Absence of tenant_id is
	// not sufficient once ADMIN_PLATFORM_CLAIM_REQUIRED is on.
	PlatformAdmin bool `json:"platform_admin,omitempty"`
	jwt.RegisteredClaims
}

func (m *manager) CreateToken() (string, error) {
	if m.config.SecretKey == "" {
		return "", ErrInvalidToken
	}
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.maxTTL())),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.SecretKey))
}

func (m *manager) ValidateToken(tokenString string) error {
	_, err := m.parse(tokenString)
	return err
}

func (m *manager) DecodeToken(tokenString string) (*Claims, error) {
	return m.parse(tokenString)
}

func (m *manager) parse(tokenString string) (*Claims, error) {
	// An empty signing key cannot authenticate anyone: a token signed with the
	// empty key is trivially forgeable, so reject every token until a key is set.
	if m.config.SecretKey == "" {
		return nil, ErrInvalidToken
	}
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(*jwt.Token) (interface{}, error) { return []byte(m.config.SecretKey), nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkewLeeway),
	)
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if time.Until(claims.ExpiresAt.Time) > m.maxTTL()+clockSkewLeeway {
		return nil, fmt.Errorf("%w: exp exceeds the %s lifetime limit", ErrInvalidToken, m.maxTTL())
	}
	return claims, nil
}

func (m *manager) maxTTL() time.Duration {
	if m.config.AdminTokenMaxTTL > 0 {
		return m.config.AdminTokenMaxTTL
	}
	return config.DefaultAdminTokenMaxTTL
}
