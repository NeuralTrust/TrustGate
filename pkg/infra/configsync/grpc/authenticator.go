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
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/golang-jwt/jwt/v5"
)

var signedTokenAlgorithms = []string{"HS256"}

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
	secrets [][]byte
}

func newJWTAuthenticator(cfg config.ConfigSyncConfig) (*jwtAuthenticator, error) {
	if cfg.JWTSecret == "" {
		return nil, errors.New("config-sync signed mode requires a JWT shared secret")
	}
	secrets := [][]byte{[]byte(cfg.JWTSecret)}
	if cfg.JWTSecretPrevious != "" {
		secrets = append(secrets, []byte(cfg.JWTSecretPrevious))
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
		secrets: secrets,
	}, nil
}

func (j *jwtAuthenticator) authenticate(bearer string) (string, error) {
	if bearer == "" {
		return "", errUnauthenticated
	}
	for _, secret := range j.secrets {
		claims := jwt.MapClaims{}
		if _, err := j.parser.ParseWithClaims(bearer, claims, func(*jwt.Token) (any, error) { return secret, nil }); err != nil {
			continue
		}
		scope, ok := claims["scope"].(string)
		if !ok || scope == "" {
			return "", errUnauthenticated
		}
		return scope, nil
	}
	return "", errUnauthenticated
}

// compositeAuthenticator accepts either a signed per-tenant JWT (external data
// planes → scoped snapshot) or the shared bearer token (in-cluster data plane →
// global snapshot). The JWT is verified first; only a bearer that fails JWT
// verification is compared against the shared token in constant time. This lets a
// single control plane serve an internal shared fleet and external per-tenant
// data planes at once, without the shared secret ever leaving the cluster.
type compositeAuthenticator struct {
	jwt    *jwtAuthenticator
	shared *sharedAuthenticator
}

func newCompositeAuthenticator(cfg config.ConfigSyncConfig) (*compositeAuthenticator, error) {
	jwtAuth, err := newJWTAuthenticator(cfg)
	if err != nil {
		return nil, err
	}
	return &compositeAuthenticator{jwt: jwtAuth, shared: newSharedAuthenticator(cfg)}, nil
}

func (c *compositeAuthenticator) authenticate(bearer string) (string, error) {
	if scope, err := c.jwt.authenticate(bearer); err == nil {
		return scope, nil
	}
	return c.shared.authenticate(bearer)
}
