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

// Package complexity is a client for the Firewall Complexity API, which scores
// the complexity of a user message in [0,1] so the load balancer can route by
// difficulty.
package complexity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
)

const (
	complexityPath   = "/v1/complexity"
	headerToken      = "token"
	contentTypeJSON  = "application/json"
	maxResponseBytes = 1 << 20
	defaultTimeout   = 15 * time.Second

	configPath = "/v1/complexity/config"
	// defaultMaxInputChars mirrors the firewall's default per-request limit
	// (max_input_chars), used until /config answers or when it is unavailable.
	defaultMaxInputChars = 32768
	configTimeout        = 2 * time.Second
	configTTL            = 5 * time.Minute
	configFailureTTL     = 30 * time.Second

	// peerService must match the firewall gateway's own service.name, and
	// scoreSpanName stays a bounded label rather than the request target.
	peerService   = "firewall-gateway"
	scoreSpanName = "firewall.complexity"
)

// ErrUnauthorized is returned when the Firewall Complexity API rejects the token.
var ErrUnauthorized = errors.New("complexity: unauthorized")

// ErrNotConfigured is returned when Score is called without a base URL and token provider.
var ErrNotConfigured = errors.New("complexity: client not configured")

// ErrInputTooLarge is returned when the firewall rejects the input with 413
// even after it was cut to the published limits.
var ErrInputTooLarge = errors.New("complexity: input exceeds firewall limit")

// TokenProvider supplies authentication tokens for Firewall requests.
type TokenProvider interface {
	Configured() bool
	Invalidate()
	Token() (string, error)
}

// Client calls the Firewall Complexity API.
type Client struct {
	http             *http.Client
	baseURL          string
	tokenProvider    TokenProvider
	expectedRevision string

	// limitsMu guards only the swap and read of the cached value, never I/O.
	limitsMu        sync.Mutex
	limits          inputLimits
	limitsLoaded    bool
	limitsExpiresAt time.Time
	refreshing      atomic.Bool
}

// NewClient builds a Client. Missing endpoint credentials leave it unconfigured.
func NewClient(baseURL string, tokenProvider TokenProvider, timeout time.Duration, expectedRevision string) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: o11y.InternalTransport(peerService, scoreSpanName),
		},
		baseURL:          strings.TrimRight(baseURL, "/"),
		tokenProvider:    tokenProvider,
		expectedRevision: strings.TrimSpace(expectedRevision),
	}
}

// Configured reports whether the endpoint and token provider are configured.
func (c *Client) Configured() bool {
	return c.baseURL != "" && c.tokenProvider != nil && c.tokenProvider.Configured() && c.expectedRevision != ""
}

// ScoreSR1 returns an unsmoothed score only from the immutable SR-1 model.
func (c *Client) ScoreSR1(ctx context.Context, input, tenantID string) (float64, error) {
	return c.score(ctx, input, tenantID)
}

func (c *Client) score(ctx context.Context, input, tenantID string) (float64, error) {
	if !c.Configured() {
		return 0, ErrNotConfigured
	}
	token, err := c.tokenProvider.Token()
	if err != nil {
		return 0, fmt.Errorf("complexity: get token: %w", err)
	}
	input = c.truncate(token, input)
	payload, err := json.Marshal(scoreRequest{
		Input:    input,
		TenantID: tenantID,
	})
	if err != nil {
		return 0, fmt.Errorf("complexity: marshal request: %w", err)
	}
	endpoint := c.baseURL + complexityPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("complexity: build request: %w", err)
	}
	req.Header.Set(headerToken, token)
	req.Header.Set("Content-Type", contentTypeJSON)

	res, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("complexity: score call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return 0, fmt.Errorf("complexity: read response: %w", err)
	}
	if res.StatusCode == http.StatusUnauthorized {
		c.tokenProvider.Invalidate()
		return 0, ErrUnauthorized
	}
	if res.StatusCode == http.StatusRequestEntityTooLarge {
		return 0, fmt.Errorf("%w (status 413, sent %d chars)", ErrInputTooLarge, utf8.RuneCountInString(input))
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return 0, fmt.Errorf("complexity: unexpected status %d", res.StatusCode)
	}
	var out scoreResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("complexity: decode response: %w", err)
	}
	if out.Revision != c.expectedRevision || out.RawScore == nil {
		return 0, errors.New("complexity: frozen routing score provenance unavailable")
	}
	return *out.RawScore, nil
}

// truncate cuts input to the firewall's published limit, counted in runes
// (the firewall counts Python len, i.e. Unicode code points) and cut on a rune
// boundary. Cutting is safe for scoring: the complexity model only reads the
// first COMPLEXITY_MAX_LENGTH=256 tokens, so text beyond the limit cannot
// change the score, whereas a 413 would silently route to the strongest rung.
// Input within the limit is returned unchanged.
func (c *Client) truncate(token, input string) string {
	limit := c.currentLimits(token).effective()
	if limit <= 0 || len(input) <= limit { // len >= rune count, so bytes <= limit is within it
		return input
	}
	count := 0
	for i := range input {
		if count == limit {
			return input[:i]
		}
		count++
	}
	return input
}

// currentLimits returns the cached limits (the defaults before the first
// successful fetch) immediately. When they are stale it starts at most one
// background refresh, so scoring never waits on /config.
func (c *Client) currentLimits(token string) inputLimits {
	c.limitsMu.Lock()
	limits, stale := c.cachedLocked(), !time.Now().Before(c.limitsExpiresAt)
	c.limitsMu.Unlock()
	if stale && c.refreshing.CompareAndSwap(false, true) {
		go func() {
			defer c.refreshing.Store(false)
			ctx, cancel := context.WithTimeout(context.Background(), configTimeout)
			defer cancel()
			_ = c.refresh(ctx, token)
		}()
	}
	return limits
}

func (c *Client) cachedLocked() inputLimits {
	if c.limitsLoaded {
		return c.limits
	}
	return inputLimits{MaxInputChars: intPtr(defaultMaxInputChars)}
}

// refresh fetches /config and swaps the cache. On failure the last known
// limits stay in place and the next attempt waits configFailureTTL.
func (c *Client) refresh(ctx context.Context, token string) error {
	limits, err := c.fetchLimits(ctx, token)
	c.limitsMu.Lock()
	defer c.limitsMu.Unlock()
	if err != nil {
		c.limitsExpiresAt = time.Now().Add(configFailureTTL)
		return err
	}
	c.limits, c.limitsLoaded = limits, true
	c.limitsExpiresAt = time.Now().Add(configTTL)
	return nil
}

// RefreshLimits synchronously loads the firewall input limits, for warm-up at
// startup. Scoring never calls it; it refreshes in the background instead.
func (c *Client) RefreshLimits(ctx context.Context) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	token, err := c.tokenProvider.Token()
	if err != nil {
		return fmt.Errorf("complexity: get token: %w", err)
	}
	if !c.refreshing.CompareAndSwap(false, true) {
		return nil
	}
	defer c.refreshing.Store(false)
	ctx, cancel := context.WithTimeout(ctx, configTimeout)
	defer cancel()
	return c.refresh(ctx, token)
}

func (c *Client) fetchLimits(ctx context.Context, token string) (inputLimits, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+configPath, nil)
	if err != nil {
		return inputLimits{}, fmt.Errorf("complexity: build config request: %w", err)
	}
	req.Header.Set(headerToken, token)
	res, err := c.http.Do(req)
	if err != nil {
		return inputLimits{}, fmt.Errorf("complexity: config call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		return inputLimits{}, fmt.Errorf("complexity: config status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return inputLimits{}, fmt.Errorf("complexity: read config: %w", err)
	}
	var limits inputLimits
	if err := json.Unmarshal(raw, &limits); err != nil {
		return inputLimits{}, fmt.Errorf("complexity: decode config: %w", err)
	}
	return limits, nil
}

func intPtr(v int) *int { return &v }
