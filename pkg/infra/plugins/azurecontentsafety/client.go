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

package azurecontentsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20
)

type client struct {
	http *http.Client
}

func newClient() *client {
	return &client{http: &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type analyzeRequest struct {
	Text       string   `json:"text"`
	Categories []string `json:"categories,omitempty"`
	OutputType string   `json:"outputType"`
}

type categoryAnalysis struct {
	Category string `json:"category"`
	Severity int    `json:"severity"`
}

type analyzeResponse struct {
	CategoriesAnalysis []categoryAnalysis `json:"categoriesAnalysis"`
}

func (c *client) Analyze(ctx context.Context, endpoint, apiKey string, body analyzeRequest) (*analyzeResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: build request: %w", err)
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: analyze call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: read response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("azure_content_safety: unexpected status %d", res.StatusCode)
	}
	var out analyzeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("azure_content_safety: decode response: %w", err)
	}
	return &out, nil
}
