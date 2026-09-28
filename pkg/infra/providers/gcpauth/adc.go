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

package gcpauth

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// ApplicationDefaultCache mints and caches OAuth2 access tokens sourced from
// Application Default Credentials: a local `gcloud auth application-default
// login` file, a GOOGLE_APPLICATION_CREDENTIALS file, or, inside GKE/GCE, the
// attached Workload Identity / metadata-server identity. Unlike
// ServiceAccountCache, no credential material passes through TrustGate
// config or plugin settings — the identity lives entirely in the runtime
// environment, which is why it is the default for integrations that have no
// dedicated place to store a service-account JSON (e.g. the Model Armor
// plugin as of this package's introduction).
type ApplicationDefaultCache struct {
	mu      sync.RWMutex
	sources map[string]oauth2.TokenSource
	// httpClient bounds ADC resolution and every later token refresh.
	// google.DefaultTokenSource otherwise falls back to http.DefaultClient,
	// which has no timeout: a hung metadata server would block forever, and
	// because ReuseTokenSource serialises refreshes behind a mutex, every
	// concurrent caller would queue up behind the stuck one.
	httpClient *http.Client
	// find is overridden in tests to avoid touching the real ADC file/metadata lookup.
	find func(ctx context.Context, scope string) (oauth2.TokenSource, error)
}

// NewApplicationDefaultCache builds an empty ApplicationDefaultCache.
func NewApplicationDefaultCache() *ApplicationDefaultCache {
	return &ApplicationDefaultCache{
		sources:    make(map[string]oauth2.TokenSource),
		httpClient: &http.Client{Timeout: tokenRequestTimeout},
		find:       findDefaultTokenSource,
	}
}

// Token mints (or reuses a still-valid) OAuth2 access token from Application
// Default Credentials, scoped to scope.
func (c *ApplicationDefaultCache) Token(ctx context.Context, scope string) (string, error) {
	if scope == "" {
		scope = CloudPlatformScope
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	source, err := c.source(scope)
	if err != nil {
		return "", err
	}

	token, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("exchanging application default credentials for an access token: %w", err)
	}
	return token.AccessToken, nil
}

// source deliberately takes no request context. A cached source outlives the
// request that created it, so resolving ADC under a request context would tie
// every later refresh to a context that died in milliseconds. That does not
// fail uniformly: the compute token source behind Workload Identity ignores
// the context, but authorized_user credentials (a local `gcloud auth
// application-default login`) and external_account do propagate it, so once
// the access token expired every refresh would fail with context canceled
// until the process restarted. The one environment where it would not bite is
// production on GKE, which means staging would not surface it either.
func (c *ApplicationDefaultCache) source(scope string) (oauth2.TokenSource, error) {
	c.mu.RLock()
	cached, ok := c.sources[scope]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	source, err := c.find(c.resolveContext(), scope)
	if err != nil {
		return nil, fmt.Errorf("resolving application default credentials: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.sources[scope]; ok {
		return existing, nil
	}
	c.sources[scope] = source
	return source, nil
}

// resolveContext is the context ADC resolution and every later refresh run
// under: background, so it outlives the request that first triggered it, and
// carrying a bounded HTTP client so neither the lookup nor a refresh can hang
// forever. Mirrors ServiceAccountCache.
func (c *ApplicationDefaultCache) resolveContext() context.Context {
	client := c.httpClient
	if client == nil {
		client = &http.Client{Timeout: tokenRequestTimeout}
	}
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

func findDefaultTokenSource(ctx context.Context, scope string) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, scope)
}
