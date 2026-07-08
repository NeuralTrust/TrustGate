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

package grpc

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

var signedTokenAlgorithms = []string{"EdDSA", "ES256", "RS256"}

var (
	errAuthNotConfigured = errors.New("config-sync auth is not configured")
	errUnauthenticated   = errors.New("missing or invalid config-sync token")
)

type scopeAuthenticator interface {
	authenticate(bearer string) (scope string, err error)
}

type sharedAuthenticator struct {
	tokenDigests [][32]byte
}

func newSharedAuthenticator(cfg config.ConfigSyncConfig) *sharedAuthenticator {
	auth := &sharedAuthenticator{}
	if cfg.Token != "" {
		auth.tokenDigests = append(auth.tokenDigests, sha256.Sum256([]byte(cfg.Token)))
		if cfg.TokenPrevious != "" {
			auth.tokenDigests = append(auth.tokenDigests, sha256.Sum256([]byte(cfg.TokenPrevious)))
		}
	}
	return auth
}

func (s *sharedAuthenticator) configured() bool { return len(s.tokenDigests) > 0 }

func (s *sharedAuthenticator) authenticate(bearer string) (string, error) {
	if !s.configured() {
		return "", errAuthNotConfigured
	}
	if bearer == "" {
		return "", errUnauthenticated
	}
	providedDigest := sha256.Sum256([]byte(bearer))
	matched := 0
	for _, digest := range s.tokenDigests {
		matched |= subtle.ConstantTimeCompare(providedDigest[:], digest[:])
	}
	if matched != 1 {
		return "", errUnauthenticated
	}
	return "", nil
}

type jwtAuthenticator struct {
	parser  *jwt.Parser
	keyfunc jwt.Keyfunc
}

func newJWTAuthenticator(cfg config.ConfigSyncConfig) (*jwtAuthenticator, error) {
	if cfg.JWTPublicKey == "" {
		return nil, errors.New("config-sync signed mode requires a JWT public key")
	}
	key, err := parsePKIXPublicKeyPEM(cfg.JWTPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse config-sync JWT public key: %w", err)
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(signedTokenAlgorithms),
		jwt.WithExpirationRequired(),
	}
	if cfg.JWTIssuer != "" {
		opts = append(opts, jwt.WithIssuer(cfg.JWTIssuer))
	}
	if cfg.JWTAudience != "" {
		opts = append(opts, jwt.WithAudience(cfg.JWTAudience))
	}
	return &jwtAuthenticator{
		parser:  jwt.NewParser(opts...),
		keyfunc: func(*jwt.Token) (any, error) { return key, nil },
	}, nil
}

func (j *jwtAuthenticator) authenticate(bearer string) (string, error) {
	if bearer == "" {
		return "", errUnauthenticated
	}
	claims := jwt.MapClaims{}
	if _, err := j.parser.ParseWithClaims(bearer, claims, j.keyfunc); err != nil {
		return "", errUnauthenticated
	}
	scope, ok := claims["scope"].(string)
	if !ok || scope == "" {
		return "", errUnauthenticated
	}
	return scope, nil
}

func parsePKIXPublicKeyPEM(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
