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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

// defaultTokenTTL bounds the lifetime of tokens minted by CreateToken so a
// self-issued token cannot live forever.
const defaultTokenTTL = 24 * time.Hour

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
	TeamID    string `json:"team_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Purpose restricts where a token is accepted. Empty means a regular
	// admin token; "playground" tokens are only valid on the proxy plane.
	Purpose string `json:"purpose,omitempty"`
	// ConsumerSlug binds a playground token to a single consumer route.
	ConsumerSlug string `json:"consumer_slug,omitempty"`
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
			ExpiresAt: jwt.NewNumericDate(now.Add(defaultTokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.config.SecretKey))
}

func (m *manager) ValidateToken(tokenString string) error {
	// An empty signing key cannot authenticate anyone: a token signed with the
	// empty key is trivially forgeable, so reject every token until a key is set.
	if m.config.SecretKey == "" {
		return ErrInvalidToken
	}
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, []byte(m.config.SecretKey))
	h.Write([]byte(signingInput))
	expectedSig := h.Sum(nil)

	providedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrInvalidToken
	}

	if !hmac.Equal(expectedSig, providedSig) {
		return ErrInvalidToken
	}

	if exp, ok := m.extractExpiration(parts[1]); ok {
		if time.Now().After(exp) {
			return ErrExpiredToken
		}
	}

	return nil
}

func (m *manager) extractExpiration(payloadB64 string) (time.Time, bool) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return time.Time{}, false
	}

	var payload struct {
		Exp *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return time.Time{}, false
	}

	if payload.Exp == nil {
		return time.Time{}, false
	}

	expInt, err := payload.Exp.Int64()
	if err != nil {
		return time.Time{}, false
	}

	return time.Unix(expInt, 0), true
}

func (m *manager) DecodeToken(tokenString string) (*Claims, error) {
	if m.config.SecretKey == "" {
		return nil, ErrInvalidToken
	}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(m.config.SecretKey), nil
		},
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
