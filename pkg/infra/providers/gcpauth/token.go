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

// Package gcpauth provides shared Google Cloud Platform authentication
// primitives for TrustGate providers and plugins that call GCP-hosted APIs
// (Vertex AI, Model Armor, …). Three credential sources are supported:
//
//   - ServiceAccountCache mints tokens from an explicit service-account JSON
//     credential, e.g. one configured on a provider connection.
//   - ApplicationDefaultCache mints tokens from Application Default
//     Credentials / GKE Workload Identity, i.e. the ambient credential of the
//     process, with nothing stored in TrustGate at all.
//   - ImpersonationCache mints tokens for a target service account named only
//     by its email, by having the ambient identity (ApplicationDefaultCache)
//     impersonate it through the IAM Credentials API. This is the keyless,
//     per-tenant path: a customer grants our ambient identity
//     roles/iam.serviceAccountTokenCreator on a service account they control,
//     and nothing about the grant is stored in TrustGate either.
//
// Callers pick the source that matches what they store: a plugin that has no
// place to keep a service-account JSON should use ApplicationDefaultCache or
// ImpersonationCache rather than growing one.
package gcpauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// CloudPlatformScope is the broad GCP OAuth scope covering Vertex AI,
	// Model Armor and other Cloud Platform APIs.
	CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform" // #nosec G101 -- OAuth scope, not a credential value

	tokenRequestTimeout   = 10 * time.Second
	maxCachedTokenSources = 256
)

// ServiceAccountCache mints and caches OAuth2 access tokens for explicit
// service-account JSON credentials. Sources are keyed by a hash of the
// credential and scope so that unrelated service accounts (different
// tenants, different scopes) never share a cached token.
type ServiceAccountCache struct {
	httpClient *http.Client
	mu         sync.RWMutex
	sources    map[string]oauth2.TokenSource
}

// NewServiceAccountCache builds an empty ServiceAccountCache.
func NewServiceAccountCache() *ServiceAccountCache {
	return &ServiceAccountCache{
		httpClient: &http.Client{Timeout: tokenRequestTimeout},
		sources:    make(map[string]oauth2.TokenSource),
	}
}

// Token mints (or reuses a still-valid) OAuth2 access token for
// serviceAccountJSON, scoped to scope.
func (c *ServiceAccountCache) Token(ctx context.Context, serviceAccountJSON, scope string) (string, error) {
	if serviceAccountJSON == "" {
		return "", fmt.Errorf("gcp service account credentials are required")
	}
	if scope == "" {
		scope = CloudPlatformScope
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	source, err := c.source(serviceAccountJSON, scope)
	if err != nil {
		return "", err
	}

	token, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("exchanging gcp service account for an access token: %w", err)
	}
	return token.AccessToken, nil
}

func (c *ServiceAccountCache) source(serviceAccountJSON, scope string) (oauth2.TokenSource, error) {
	key := serviceAccountKey(serviceAccountJSON, scope)

	c.mu.RLock()
	cached, ok := c.sources[key]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// Rejects external_account configs, which can name a tenant-controlled local executable as their credential source.
	config, err := google.JWTConfigFromJSON([]byte(serviceAccountJSON), scope)
	if err != nil {
		return nil, fmt.Errorf("parsing gcp service account credentials: %w", err)
	}

	// A cached source outlives the request that created it, so a request context here would break every later refresh.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, c.httpClient)
	source := config.TokenSource(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.sources[key]; ok {
		return existing, nil
	}
	// Rebuilding a source is cheap, so drop the cache rather than let key rotations grow it without bound.
	if len(c.sources) >= maxCachedTokenSources {
		clear(c.sources)
	}
	c.sources[key] = source
	return source, nil
}

func serviceAccountKey(serviceAccountJSON, scope string) string {
	return hashKey(serviceAccountJSON, scope)
}

// hashKey derives a cache key from two credential-identifying strings (a
// service-account JSON or a target email, plus a scope) so that unrelated
// credentials never collide in a cache keyed by string equality alone.
// Shared by ServiceAccountCache and ImpersonationCache.
func hashKey(a, b string) string {
	sum := sha256.Sum256([]byte(a + "\x00" + b))
	return hex.EncodeToString(sum[:])
}
