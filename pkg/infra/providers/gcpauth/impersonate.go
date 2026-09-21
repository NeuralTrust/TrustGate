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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// iamCredentialsEndpoint is GCP's IAM Credentials API host. There is only
	// one, unlike Model Armor's per-region hosts: generateAccessToken is a
	// control-plane call, not a data-plane one.
	iamCredentialsEndpoint = "https://iamcredentials.googleapis.com/v1"

	maxImpersonateResponseBytes = 1 << 16
)

// ImpersonationCache mints and caches OAuth2 access tokens by impersonating a
// target service account, named only by its email, through GCP's IAM
// Credentials API (projects/-/serviceAccounts/{email}:generateAccessToken).
// The caller of that API is always this process's own Application Default
// Credentials / Workload Identity — the ambient identity ApplicationDefaultCache
// resolves — so no secret about the target ever passes through TrustGate: the
// customer grants that ambient identity roles/iam.serviceAccountTokenCreator
// on a service account they control in their own project, and revoking that
// one grant is enough to cut us off. This is the keyless credential path: an
// email is not a credential, it is useless without the customer's own grant.
//
// Sources are keyed by a hash of email+scope, mirroring ServiceAccountCache,
// so unrelated target service accounts (different tenants, different
// policies) never share a cached token.
type ImpersonationCache struct {
	base       *ApplicationDefaultCache
	httpClient *http.Client
	endpoint   string // overridden in tests; defaults to iamCredentialsEndpoint
	mu         sync.RWMutex
	sources    map[string]oauth2.TokenSource
}

// NewImpersonationCache builds an empty ImpersonationCache that authenticates
// its generateAccessToken calls with base's Application Default Credentials.
func NewImpersonationCache(base *ApplicationDefaultCache) *ImpersonationCache {
	return &ImpersonationCache{
		base:       base,
		httpClient: &http.Client{Timeout: tokenRequestTimeout},
		endpoint:   iamCredentialsEndpoint,
		sources:    make(map[string]oauth2.TokenSource),
	}
}

// Token mints (or reuses a still-valid) OAuth2 access token for the service
// account named by email, scoped to scope, by impersonating it.
func (c *ImpersonationCache) Token(ctx context.Context, email, scope string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("gcp impersonation target service account email is required")
	}
	if scope == "" {
		scope = CloudPlatformScope
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	source := c.source(email, scope)
	token, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("exchanging impersonated service account %q for an access token: %w", email, err)
	}
	return token.AccessToken, nil
}

func (c *ImpersonationCache) source(email, scope string) oauth2.TokenSource {
	key := hashKey(email, scope)

	c.mu.RLock()
	cached, ok := c.sources[key]
	c.mu.RUnlock()
	if ok {
		return cached
	}

	// oauth2.ReuseTokenSource gives this the same self-caching/refreshing
	// behaviour google.DefaultTokenSource and config.TokenSource already give
	// the other two caches, so a cached entry here mints a fresh token only
	// once per hour rather than on every call.
	source := oauth2.ReuseTokenSource(nil, &impersonateTokenSource{
		httpClient: c.httpClient,
		base:       c.base,
		endpoint:   c.endpoint,
		email:      email,
		scope:      scope,
	})

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.sources[key]; ok {
		return existing
	}
	// Rebuilding a source is cheap, so drop the cache rather than let key
	// rotations (or many distinct customer service accounts) grow it without
	// bound. Mirrors ServiceAccountCache.
	if len(c.sources) >= maxCachedTokenSources {
		clear(c.sources)
	}
	c.sources[key] = source
	return source
}

// impersonateTokenSource is an oauth2.TokenSource that calls IAM Credentials'
// generateAccessToken on every Token() invocation. It is always wrapped in
// oauth2.ReuseTokenSource by the cache above, so in steady state Token() only
// runs again once the previously minted token is close to its ~1 hour
// expiry.
type impersonateTokenSource struct {
	httpClient *http.Client
	base       *ApplicationDefaultCache
	endpoint   string
	email      string
	scope      string
}

type generateAccessTokenRequest struct {
	Scope []string `json:"scope"`
}

type generateAccessTokenResponse struct {
	AccessToken string    `json:"accessToken"`
	ExpireTime  time.Time `json:"expireTime"`
}

func (s *impersonateTokenSource) Token() (*oauth2.Token, error) {
	// Background, bounded only by httpClient.Timeout: a cached source outlives
	// the request that first built it (mirrors
	// ApplicationDefaultCache.resolveContext), so tying this to a request
	// context would break every later refresh once that request's context is
	// gone.
	ctx := context.Background()

	callerToken, err := s.base.Token(ctx, CloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("resolving ambient credentials to impersonate %q: %w", s.email, err)
	}

	payload, err := json.Marshal(generateAccessTokenRequest{Scope: []string{s.scope}})
	if err != nil {
		return nil, fmt.Errorf("marshal generateAccessToken request: %w", err)
	}

	endpoint := s.endpoint
	if endpoint == "" {
		endpoint = iamCredentialsEndpoint
	}
	url := fmt.Sprintf("%s/projects/-/serviceAccounts/%s:generateAccessToken", endpoint, s.email)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build generateAccessToken request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generateAccessToken call for %q: %w", s.email, err)
	}
	defer drainAndClose(res.Body)

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxImpersonateResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read generateAccessToken response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("generateAccessToken for %q: unexpected status %d: %s",
			s.email, res.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out generateAccessTokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode generateAccessToken response: %w", err)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("generateAccessToken for %q returned no access token", s.email)
	}
	return &oauth2.Token{AccessToken: out.AccessToken, TokenType: "Bearer", Expiry: out.ExpireTime}, nil
}

// drainAndClose reads and discards up to 64 KB of remaining data from r, then
// closes it, so the connection can be reused cleanly. Mirrors
// providers.DrainBody; duplicated locally rather than imported so gcpauth
// stays free of a dependency on its sibling providers package.
func drainAndClose(r io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, maxImpersonateResponseBytes))
	_ = r.Close()
}
