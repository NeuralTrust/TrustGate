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

// Package secretstore models the customer's secret managers that
// customer-operated planes read referenced credentials from. Stores are
// declared in the deployment's own configuration, never through the API, and
// no TrustGate database holds their address, credentials or values.
package secretstore

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// Type is the kind of secret manager a store reads from.
type Type string

// Store types.
const (
	TypeHashiCorpVault    Type = "hashicorp_vault"
	TypeAWSSecretsManager Type = "aws_secrets_manager"
	TypeGCPSecretManager  Type = "gcp_secret_manager" // #nosec G101 -- store type identifier, not a credential
	TypeAzureKeyVault     Type = "azure_key_vault"
	TypeCyberArkConjur    Type = "cyberark_conjur"
	TypeFile              Type = "file"
	TypeEnv               Type = "env"
)

// Defaults of SECRET_STORES_FETCH_TIMEOUT, SECRET_STORES_REFRESH_INTERVAL and
// SECRET_STORES_PROBE_INTERVAL, shared by the configuration and the planes.
const (
	DefaultFetchTimeout    = 2 * time.Second
	DefaultRefreshInterval = 15 * time.Second
	DefaultProbeInterval   = 60 * time.Second
)

// AllPaths, written explicitly in AllowedPaths, admits every path.
const AllPaths = "*"

// Cache policy defaults and the shortest TTL a store may set.
const (
	DefaultTTL         = 5 * time.Minute
	DefaultMaxStale    = 24 * time.Hour
	DefaultNegativeTTL = 30 * time.Second
	MinTTL             = 30 * time.Second
)

// CachePolicy is how long a plane keeps what it read from a store. Zero
// fields take the defaults.
type CachePolicy struct {
	TTL         time.Duration
	MaxStale    time.Duration
	NegativeTTL time.Duration
}

// WithDefaults returns p with every zero field set to its default.
func (p CachePolicy) WithDefaults() CachePolicy {
	if p.TTL == 0 {
		p.TTL = DefaultTTL
	}
	if p.MaxStale == 0 {
		p.MaxStale = DefaultMaxStale
	}
	if p.NegativeTTL == 0 {
		p.NegativeTTL = DefaultNegativeTTL
	}
	return p
}

// Validate checks p after defaults.
func (p CachePolicy) Validate() error {
	p = p.WithDefaults()
	switch {
	case p.TTL < MinTTL:
		return fmt.Errorf("%w: cache.ttl must be at least %s", ErrInvalidStore, MinTTL)
	case p.MaxStale < 0:
		return fmt.Errorf("%w: cache.max_stale must not be negative", ErrInvalidStore)
	case p.NegativeTTL < 0:
		return fmt.Errorf("%w: cache.negative_ttl must not be negative", ErrInvalidStore)
	}
	return nil
}

// Store is one declared secret store. Config holds the pointer to the typed
// configuration of Type (for example *HashiCorpVaultConfig).
type Store struct {
	Name         string
	Type         Type
	AllowedPaths []string
	Gateways     []ids.GatewayID
	Cache        CachePolicy
	Config       TypedConfig
}

// TypedConfig is the type-specific part of a store.
type TypedConfig interface {
	StoreType() Type
	Validate() error
}

// Validate checks the store as a whole: name, allowed paths, cache policy and
// a configuration that matches its type.
func (s *Store) Validate() error {
	if !secretref.ValidStoreName(s.Name) {
		return fmt.Errorf("%w: name %q must be 1-63 characters of [a-z0-9_-] starting with a letter or digit", ErrInvalidStore, s.Name)
	}
	if len(s.AllowedPaths) == 0 {
		return fmt.Errorf("%w: store %q: allowed_paths is required; write %q to allow every path", ErrInvalidStore, s.Name, AllPaths)
	}
	for _, p := range s.AllowedPaths {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("%w: store %q: allowed_paths must not contain an empty prefix", ErrInvalidStore, s.Name)
		}
		if strings.HasPrefix(p, "/") {
			return fmt.Errorf("%w: store %q: allowed path %q must not start with \"/\"; reference paths never do", ErrInvalidStore, s.Name, p)
		}
	}
	for _, gw := range s.Gateways {
		if gw.IsNil() {
			return fmt.Errorf("%w: store %q: gateways must not contain a nil id", ErrInvalidStore, s.Name)
		}
	}
	if err := s.Cache.Validate(); err != nil {
		return fmt.Errorf("store %q: %w", s.Name, err)
	}
	if s.Config == nil {
		return fmt.Errorf("%w: store %q: the %s configuration is missing", ErrInvalidStore, s.Name, s.Type)
	}
	if s.Config.StoreType() != s.Type {
		return fmt.Errorf("%w: store %q: type %q does not match a %s configuration", ErrInvalidStore, s.Name, s.Type, s.Config.StoreType())
	}
	if err := s.Config.Validate(); err != nil {
		return fmt.Errorf("store %q: %w", s.Name, err)
	}
	return nil
}

// AdmitsGateway reports whether gw may use the store. An empty allowlist
// admits every gateway the plane serves and finds eligible.
func (s *Store) AdmitsGateway(gw ids.GatewayID) bool {
	if len(s.Gateways) == 0 {
		return true
	}
	for _, allowed := range s.Gateways {
		if allowed == gw {
			return true
		}
	}
	return false
}

// AllowsPath reports whether path, the decoded path of a reference, starts
// with one of the store's allowed prefixes. AllPaths matches only when
// written explicitly.
func (s *Store) AllowsPath(path string) bool {
	for _, prefix := range s.AllowedPaths {
		if prefix == AllPaths || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// Allows checks that gw may read path from the store. It returns
// ErrNotAllowed when the allowlist excludes gw and ErrPathNotAllowed when the
// path is outside the allowed prefixes.
func (s *Store) Allows(gw ids.GatewayID, path string) error {
	if !s.AdmitsGateway(gw) {
		return fmt.Errorf("store %q: %w", s.Name, ErrNotAllowed)
	}
	if !s.AllowsPath(path) {
		return fmt.Errorf("store %q: %w", s.Name, ErrPathNotAllowed)
	}
	return nil
}
