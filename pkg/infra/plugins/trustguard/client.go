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

package trustguard

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
	evaluatePath     = "/v1/evaluate"
	traceIDHeader    = "X-Trace-ID"
	maxResponseBytes = 1 << 20
)

var errUnauthorized = errors.New("trustguard: unauthorized")

// rateLimitHeaderNames are forwarded from TrustGuard evaluate 429 to the gateway client.
var rateLimitHeaderNames = []string{
	"Retry-After",
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reason",
}

type rateLimitedError struct {
	headers map[string][]string
	body    []byte
}

func (e *rateLimitedError) Error() string {
	return "trustguard: rate limit exceeded"
}

type client struct {
	http *http.Client
}

func newClient(timeout time.Duration) *client {
	return &client{http: &http.Client{Timeout: timeout}}
}

func (c *client) Guard(ctx context.Context, baseURL, token, traceID string, body GuardRequest) (*GuardResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("trustguard: marshal request: %w", err)
	}
	endpoint := strings.TrimRight(baseURL, "/") + evaluatePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("trustguard: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentTypeJSON)
	if traceID != "" {
		req.Header.Set(traceIDHeader, traceID)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustguard: guard call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("trustguard: read response: %w", err)
	}
	if res.StatusCode == http.StatusUnauthorized {
		return nil, errUnauthorized
	}
	if res.StatusCode == http.StatusTooManyRequests {
		return nil, &rateLimitedError{
			headers: copyRateLimitHeaders(res.Header),
			body:    append([]byte(nil), raw...),
		}
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("trustguard: unexpected status %d", res.StatusCode)
	}
	var out GuardResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("trustguard: decode response: %w", err)
	}
	return &out, nil
}

func copyRateLimitHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(rateLimitHeaderNames))
	for _, name := range rateLimitHeaderNames {
		values := h.Values(name)
		if len(values) == 0 {
			continue
		}
		out[name] = append([]string(nil), values...)
	}
	return out
}
