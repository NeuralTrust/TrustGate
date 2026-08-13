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

package vertex

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

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	cloudPlatformScope    = "https://www.googleapis.com/auth/cloud-platform" // #nosec G101 -- OAuth scope, not a credential value
	tokenRequestTimeout   = 10 * time.Second
	maxCachedTokenSources = 256
)

var defaultTokenCache = newTokenCache()

type tokenSource func(context.Context, *providers.GCP) (string, error)

type tokenCache struct {
	httpClient *http.Client
	mu         sync.RWMutex
	sources    map[string]oauth2.TokenSource
}

func newTokenCache() *tokenCache {
	return &tokenCache{
		httpClient: &http.Client{Timeout: tokenRequestTimeout},
		sources:    make(map[string]oauth2.TokenSource),
	}
}

func (c *tokenCache) token(ctx context.Context, gcp *providers.GCP) (string, error) {
	if gcp == nil || gcp.ServiceAccountJSON == "" {
		return "", fmt.Errorf("gcp service account credentials are required for Vertex AI")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	source, err := c.source(gcp.ServiceAccountJSON)
	if err != nil {
		return "", err
	}

	token, err := source.Token()
	if err != nil {
		return "", fmt.Errorf("exchanging gcp service account for an access token: %w", err)
	}
	return token.AccessToken, nil
}

func (c *tokenCache) source(serviceAccountJSON string) (oauth2.TokenSource, error) {
	key := serviceAccountKey(serviceAccountJSON)

	c.mu.RLock()
	cached, ok := c.sources[key]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}

	// Rejects external_account configs, which can name a tenant-controlled local executable as their credential source.
	config, err := google.JWTConfigFromJSON([]byte(serviceAccountJSON), cloudPlatformScope)
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

func serviceAccountKey(serviceAccountJSON string) string {
	sum := sha256.Sum256([]byte(serviceAccountJSON))
	return hex.EncodeToString(sum[:])
}
