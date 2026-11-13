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

package watsonx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	iamTokenURL     = "https://iam.cloud.ibm.com/identity/token" // #nosec G101 -- public IBM Cloud IAM endpoint, not a credential
	iamAPIKeyGrant  = "urn:ibm:params:oauth:grant-type:apikey"   // #nosec G101 -- OAuth grant type identifier, not a credential
	iamTimeout      = 10 * time.Second
	iamMaxBody      = 64 << 10
	maxCachedTokens = 256

	// IBM asks clients to refresh once 80% of a token's lifetime has passed.
	refreshNumerator   = 4
	refreshDenominator = 5
	// A token this close to its expiry is not handed out even when a refresh
	// failed: the call it authenticates could outlive it.
	expirySafety = 30 * time.Second
)

var errIAMRejected = errors.New("IBM Cloud IAM rejected the API key")

type iamToken struct {
	accessToken string
	refreshAt   time.Time
	expiresAt   time.Time
}

// tokenCache exchanges IBM Cloud API keys for IAM bearer tokens and keeps each
// one until it is due for a refresh. Keys are held only as SHA-256 digests.
type tokenCache struct {
	tokenURL string
	pool     *providers.HTTPClientPool
	now      func() time.Time

	mu     sync.Mutex
	tokens map[string]iamToken
	flight singleflight.Group
}

func newTokenCache(tokenURL string) *tokenCache {
	return &tokenCache{
		tokenURL: tokenURL,
		pool:     providers.NewHTTPClientPool(),
		now:      time.Now,
		tokens:   make(map[string]iamToken),
	}
}

func cacheKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

func (c *tokenCache) token(ctx context.Context, apiKey string) (string, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return "", fmt.Errorf("%w: an IBM Cloud API key is required for watsonx.ai", registry.ErrCredentialAcquisition)
	}
	key := cacheKey(apiKey)

	cached, ok := c.cached(key)
	now := c.now()
	if ok && now.Before(cached.refreshAt) {
		return cached.accessToken, nil
	}

	result := c.flight.DoChan(key, func() (any, error) {
		if fresh, ok := c.cached(key); ok && c.now().Before(fresh.refreshAt) {
			return fresh, nil
		}
		// The exchange is shared by every waiting request, so one caller
		// giving up must not fail the others.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), iamTimeout)
		defer cancel()
		minted, err := c.exchange(fetchCtx, apiKey)
		if err != nil {
			return nil, err
		}
		c.store(key, minted)
		return minted, nil
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-result:
		if res.Err != nil {
			if ok && !errors.Is(res.Err, errIAMRejected) && c.now().Add(expirySafety).Before(cached.expiresAt) {
				return cached.accessToken, nil
			}
			return "", fmt.Errorf("%w: %w", registry.ErrCredentialAcquisition, res.Err)
		}
		tok, _ := res.Val.(iamToken)
		return tok.accessToken, nil
	}
}

// invalidate drops the cached token for apiKey when it is still the one a
// request was refused with, so the next call mints a new one.
func (c *tokenCache) invalidate(apiKey, refused string) {
	key := cacheKey(strings.TrimSpace(apiKey))
	c.mu.Lock()
	defer c.mu.Unlock()
	if tok, ok := c.tokens[key]; ok && tok.accessToken == refused {
		delete(c.tokens, key)
	}
}

func (c *tokenCache) cached(key string) (iamToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, ok := c.tokens[key]
	return tok, ok
}

func (c *tokenCache) store(key string, tok iamToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.tokens[key]; !exists && len(c.tokens) >= maxCachedTokens {
		clear(c.tokens)
	}
	c.tokens[key] = tok
}

type iamTokenResponse struct {
	AccessToken string `json:"access_token"` // #nosec G117 -- IAM response field
	ExpiresIn   int64  `json:"expires_in"`
	Expiration  int64  `json:"expiration"`
}

type iamErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

func (c *tokenCache) exchange(ctx context.Context, apiKey string) (iamToken, error) {
	form := url.Values{}
	form.Set("grant_type", iamAPIKeyGrant)
	form.Set("apikey", apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return iamToken{}, fmt.Errorf("building IBM Cloud IAM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	issuedAt := c.now()
	resp, err := c.pool.Get("watsonx-iam", iamTimeout).Do(req) // #nosec G704 -- token URL is the fixed IBM Cloud IAM endpoint
	if err != nil {
		return iamToken{}, fmt.Errorf("calling IBM Cloud IAM: %w", err)
	}
	defer providers.DrainBody(resp.Body)

	body, err := io.ReadAll(io.LimitReader(resp.Body, iamMaxBody))
	if err != nil {
		return iamToken{}, fmt.Errorf("reading IBM Cloud IAM response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return iamToken{}, iamStatusError(resp.StatusCode, body)
	}

	var parsed iamTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		return iamToken{}, errors.New("IBM Cloud IAM returned no access token")
	}

	lifetime := time.Duration(parsed.ExpiresIn) * time.Second
	if lifetime <= 0 && parsed.Expiration > 0 {
		lifetime = time.Unix(parsed.Expiration, 0).Sub(issuedAt)
	}
	if lifetime <= 0 {
		return iamToken{}, errors.New("IBM Cloud IAM returned a token without a lifetime")
	}
	return iamToken{
		accessToken: parsed.AccessToken,
		refreshAt:   issuedAt.Add(lifetime * refreshNumerator / refreshDenominator),
		expiresAt:   issuedAt.Add(lifetime),
	}, nil
}

func iamStatusError(status int, body []byte) error {
	var parsed iamErrorResponse
	_ = json.Unmarshal(body, &parsed)
	detail := strings.TrimSpace(parsed.ErrorMessage)
	if parsed.ErrorCode != "" {
		detail = strings.TrimSpace(parsed.ErrorCode + " " + detail)
	}
	if detail == "" {
		detail = http.StatusText(status)
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w (status %d): %s", errIAMRejected, status, detail)
	default:
		return fmt.Errorf("IBM Cloud IAM returned status %d: %s", status, detail)
	}
}
