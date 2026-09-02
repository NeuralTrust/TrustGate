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
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

// AudiencePlayground is the audience RS256 playground tokens must carry, so a
// token minted for the playground can never double as an admin M2M credential
// (and vice versa: M2M tokens carry aud trustgate-admin and token_use).
const AudiencePlayground = "trustgate-playground"

// PlaygroundKeySource supplies the RSA public keys, by kid, trusted to have
// signed RS256 playground tokens. Implementations may be static (env config)
// or live (config-sync snapshot on data planes); the verifier reads it per
// token so key rotation needs no restart.
type PlaygroundKeySource interface {
	PlaygroundTokenKeys() map[string]*rsa.PublicKey
}

// PlaygroundVerifier authenticates playground tokens. Two signature schemes
// are accepted: RS256 minted by the control plane and verified against the
// PlaygroundKeySource (how hybrid data planes validate without sharing any
// secret), and the legacy HS256 signed with this deployment's own
// SERVER_SECRET_KEY (self-hosted installs where dashboard and gateway share
// it). Claim checks (purpose, consumer binding) stay in the identity resolver.
type PlaygroundVerifier interface {
	Verify(tokenString string) (*Claims, error)
}

type playgroundVerifier struct {
	serverCfg *config.ServerConfig
	source    PlaygroundKeySource
}

func NewPlaygroundVerifier(serverCfg *config.ServerConfig, source PlaygroundKeySource) PlaygroundVerifier {
	return &playgroundVerifier{serverCfg: serverCfg, source: source}
}

func (v *playgroundVerifier) Verify(tokenString string) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		v.keyForToken,
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg(), jwt.SigningMethodRS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err.Error())
	}
	if _, ok := parsed.Method.(*jwt.SigningMethodRSA); ok {
		// The audience pin is what keeps admin M2M tokens (signed by the same
		// issuer) from being replayed against the playground resolver.
		if !hasAudience(claims.Audience, AudiencePlayground) {
			return nil, fmt.Errorf("%w: audience must be %s", ErrInvalidToken, AudiencePlayground)
		}
	}
	return claims, nil
}

func (v *playgroundVerifier) keyForToken(token *jwt.Token) (interface{}, error) {
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA:
		kid, _ := token.Header["kid"].(string)
		keys := map[string]*rsa.PublicKey{}
		if v.source != nil {
			keys = v.source.PlaygroundTokenKeys()
		}
		if kid != "" {
			if key, ok := keys[kid]; ok {
				return key, nil
			}
		}
		if key, ok := keys[""]; ok {
			return key, nil
		}
		if kid == "" {
			return nil, errors.New("token header is missing kid")
		}
		return nil, fmt.Errorf("unknown kid %q", kid)
	case *jwt.SigningMethodHMAC:
		if v.serverCfg == nil || v.serverCfg.SecretKey == "" {
			return nil, errors.New("shared-secret playground tokens are not configured")
		}
		return []byte(v.serverCfg.SecretKey), nil
	default:
		return nil, fmt.Errorf("unexpected signing method %q", token.Method.Alg())
	}
}

func hasAudience(aud jwt.ClaimStrings, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

// NormalizeVerificationPEM converts a configured public key (raw PEM,
// `\n`-escaped PEM, or base64-encoded PEM) into plain PEM, the only form the
// config-sync snapshot carries so data planes parse it without guessing.
func NormalizeVerificationPEM(raw string) string {
	return string(normalizePublicKeyPEM(raw))
}

// StaticPlaygroundKeys parses configured public keys into a fixed key source.
// A malformed key fails boot instead of silently shrinking the trusted set.
func StaticPlaygroundKeys(entries []config.AdminM2MPublicKey) (PlaygroundKeySource, error) {
	keys := make(map[string]*rsa.PublicKey, len(entries))
	for _, entry := range entries {
		key, err := jwt.ParseRSAPublicKeyFromPEM(normalizePublicKeyPEM(entry.PEM))
		if err != nil {
			return nil, fmt.Errorf("parse playground token public key %q: %w", entry.KID, err)
		}
		keys[entry.KID] = key
	}
	return staticKeySource(keys), nil
}

type staticKeySource map[string]*rsa.PublicKey

func (s staticKeySource) PlaygroundTokenKeys() map[string]*rsa.PublicKey { return s }

// CombinePlaygroundKeys merges key sources; later sources win on kid clashes.
// Nil sources are skipped, so callers can pass optional inputs untested.
func CombinePlaygroundKeys(sources ...PlaygroundKeySource) PlaygroundKeySource {
	return combinedKeySource(sources)
}

type combinedKeySource []PlaygroundKeySource

func (c combinedKeySource) PlaygroundTokenKeys() map[string]*rsa.PublicKey {
	merged := map[string]*rsa.PublicKey{}
	for _, source := range c {
		if source == nil {
			continue
		}
		for kid, key := range source.PlaygroundTokenKeys() {
			merged[kid] = key
		}
	}
	return merged
}
