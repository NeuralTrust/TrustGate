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
	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/golang-jwt/jwt/v5"
)

var signedTokenAlgorithms = []string{"HS256"}

var (
	errAuthNotConfigured = errors.New("config-sync auth is not configured")
	errUnauthenticated   = errors.New("missing or invalid config-sync token")
)

type tokenAuthenticator interface {
	verify(bearer string) (configsyncrevocation.Identity, error)
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

func (s *sharedAuthenticator) verify(bearer string) (configsyncrevocation.Identity, error) {
	if !s.configured() {
		return configsyncrevocation.Identity{}, errAuthNotConfigured
	}
	if bearer == "" {
		return configsyncrevocation.Identity{}, errUnauthenticated
	}
	providedDigest := sha256.Sum256([]byte(bearer))
	matched := 0
	for _, digest := range s.tokenDigests {
		matched |= subtle.ConstantTimeCompare(providedDigest[:], digest[:])
	}
	if matched != 1 {
		return configsyncrevocation.Identity{}, errUnauthenticated
	}
	return configsyncrevocation.Identity{}, nil
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

func (j *jwtAuthenticator) verify(bearer string) (configsyncrevocation.Identity, error) {
	if bearer == "" {
		return configsyncrevocation.Identity{}, errUnauthenticated
	}
	for _, secret := range j.secrets {
		claims := jwt.MapClaims{}
		if _, err := j.parser.ParseWithClaims(bearer, claims, func(*jwt.Token) (any, error) { return secret, nil }); err != nil {
			continue
		}
		id := identityFromClaims(claims)
		if id.Scope == "" {
			return configsyncrevocation.Identity{}, errUnauthenticated
		}
		return id, nil
	}
	return configsyncrevocation.Identity{}, errUnauthenticated
}

func identityFromClaims(claims jwt.MapClaims) configsyncrevocation.Identity {
	id := configsyncrevocation.Identity{Signed: true}
	if instanceID, ok := claims["instance_id"].(string); ok && instanceID != "" {
		id.Scope, id.InstanceScoped = instanceID, true
	} else if scope, ok := claims["scope"].(string); ok {
		id.Scope = scope
	}
	id.JTI, _ = claims["jti"].(string)
	id.IssuedAt = issuedAtUnix(claims)
	return id
}

// issuedAtUnix reads iat without making it mandatory: a malformed or missing
// iat only disables the issued-before rule for that token, it never rejects it.
func issuedAtUnix(claims jwt.MapClaims) int64 {
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return 0
	}
	if unix := iat.Unix(); unix > 0 {
		return unix
	}
	return 0
}

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

func (c *compositeAuthenticator) verify(bearer string) (configsyncrevocation.Identity, error) {
	if id, err := c.jwt.verify(bearer); err == nil {
		return id, nil
	}
	return c.shared.verify(bearer)
}
