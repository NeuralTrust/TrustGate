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
	"time"
)

const (
	complexityPath   = "/v1/complexity"
	headerToken      = "token"
	contentTypeJSON  = "application/json"
	maxResponseBytes = 1 << 20
	defaultTimeout   = 15 * time.Second
)

// ErrUnauthorized is returned when the Firewall Complexity API rejects the token.
var ErrUnauthorized = errors.New("complexity: unauthorized")

// ErrNotConfigured is returned when Score is called without a base URL and token.
var ErrNotConfigured = errors.New("complexity: client not configured")

// Client calls the Firewall Complexity API with a static bearer token.
type Client struct {
	http    *http.Client
	baseURL string
	token   string
}

// NewClient builds a Client. An empty baseURL or token leaves it unconfigured
// (see Configured), so callers can fall back to another strategy.
func NewClient(baseURL, token string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		http:    &http.Client{Timeout: timeout},
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
	}
}

// Configured reports whether both a base URL and token are set.
func (c *Client) Configured() bool {
	return c.baseURL != "" && c.token != ""
}

// Score returns the session-smoothed complexity score in [0,1] for input.
// conversationID and tenantID are optional and omitted from the request when empty.
func (c *Client) Score(ctx context.Context, input, conversationID, tenantID string) (float64, error) {
	if !c.Configured() {
		return 0, ErrNotConfigured
	}
	payload, err := json.Marshal(scoreRequest{
		Input:          input,
		ConversationID: conversationID,
		TenantID:       tenantID,
	})
	if err != nil {
		return 0, fmt.Errorf("complexity: marshal request: %w", err)
	}
	endpoint := c.baseURL + complexityPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("complexity: build request: %w", err)
	}
	req.Header.Set(headerToken, c.token)
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
		return 0, ErrUnauthorized
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return 0, fmt.Errorf("complexity: unexpected status %d", res.StatusCode)
	}
	var out scoreResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("complexity: decode response: %w", err)
	}
	return out.Score, nil
}
