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

package openaimoderation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	moderationsPath  = "/v1/moderations"
	maxResponseBytes = 1 << 20
)

type errModeration struct {
	status int
}

func (e *errModeration) Error() string {
	return fmt.Sprintf("openai_moderation: unexpected status %d", e.status)
}

type client struct {
	http    *http.Client
	timeout time.Duration
}

func newClient(timeout time.Duration) *client {
	return &client{
		http:    providers.NewHTTPClientPool().Get(PluginName, timeout),
		timeout: timeout,
	}
}

func (c *client) Moderate(ctx context.Context, baseURL, apiKey string, body moderationRequest) (*moderationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: marshal request: %w", err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + moderationsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: moderations call: %w", err)
	}
	defer providers.DrainBody(res.Body)

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: read response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, &errModeration{status: res.StatusCode}
	}

	var out moderationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openai_moderation: decode response: %w", err)
	}
	return &out, nil
}
