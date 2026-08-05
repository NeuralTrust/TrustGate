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

// Package firewall provides authentication for NeuralTrust Firewall clients.
package firewall

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenTTL         = time.Hour
	tokenRefreshSkew = 5 * time.Minute
)

// ErrNotConfigured is returned when a token is requested without a secret key.
var ErrNotConfigured = errors.New("firewall: token provider not configured")

// TokenProvider mints and caches short-lived Firewall JWTs.
type TokenProvider struct {
	secretKey string
	now       func() time.Time
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenProvider builds a Firewall token provider.
func NewTokenProvider(secretKey string) *TokenProvider {
	return &TokenProvider{secretKey: strings.TrimSpace(secretKey), now: time.Now}
}

// Configured reports whether the provider has a signing key.
func (p *TokenProvider) Configured() bool {
	return p != nil && p.secretKey != ""
}

// Invalidate clears the cached token.
func (p *TokenProvider) Invalidate() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.token = ""
	p.expiresAt = time.Time{}
	p.mu.Unlock()
}

// Token returns a cached token or mints a new one before the cached token expires.
func (p *TokenProvider) Token() (string, error) {
	if !p.Configured() {
		return "", ErrNotConfigured
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.token != "" && now.Before(p.expiresAt.Add(-tokenRefreshSkew)) {
		return p.token, nil
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"purpose": "firewall",
		"iat":     now.Unix(),
		"exp":     now.Add(tokenTTL).Unix(),
	})
	signed, err := token.SignedString([]byte(p.secretKey))
	if err != nil {
		return "", fmt.Errorf("firewall: sign token: %w", err)
	}
	p.token = signed
	p.expiresAt = now.Add(tokenTTL)
	return signed, nil
}
