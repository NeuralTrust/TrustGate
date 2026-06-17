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

package modelsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://models.dev"
	requestTimeout = 30 * time.Second
	// tokensPerPriceUnit converts models.dev per-million-token pricing into the
	// per-token unit the gateway uses when computing request cost.
	tokensPerPriceUnit = 1_000_000
)

// Model is a provider-native model entry as published by models.dev. Slug is the
// exact identifier the provider's own API accepts (no OpenRouter-style prefix),
// and ProviderCode is the models.dev provider key (e.g. "google-vertex").
type Model struct {
	ProviderCode  string
	Slug          string
	ExternalID    string
	DisplayName   string
	ContextWindow int
	MaxOutput     int
	InputPrice    string
	OutputPrice   string
}

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: requestTimeout},
	}
}

type apiModel struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Limit struct {
		Context int `json:"context"`
		Output  int `json:"output"`
	} `json:"limit"`
	Cost struct {
		Input  float64 `json:"input"`
		Output float64 `json:"output"`
	} `json:"cost"`
}

type apiProvider struct {
	Models map[string]apiModel `json:"models"`
}

// ListModels fetches the full models.dev catalog and flattens it into a
// provider-keyed list of native models. Entries are returned sorted by provider
// code then slug to keep sync output deterministic.
func (c *Client) ListModels(ctx context.Context) ([]Model, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("modelsdev: unexpected status %d", resp.StatusCode)
	}

	var payload map[string]apiProvider
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("modelsdev: decode response: %w", err)
	}

	out := make([]Model, 0, len(payload))
	for providerCode, provider := range payload {
		for modelID, m := range provider.Models {
			id := m.ID
			if id == "" {
				id = modelID
			}
			if id == "" {
				continue
			}
			displayName := m.Name
			if displayName == "" {
				displayName = id
			}
			out = append(out, Model{
				ProviderCode:  providerCode,
				Slug:          id,
				ExternalID:    providerCode + "/" + id,
				DisplayName:   displayName,
				ContextWindow: m.Limit.Context,
				MaxOutput:     m.Limit.Output,
				InputPrice:    formatPerTokenPrice(m.Cost.Input),
				OutputPrice:   formatPerTokenPrice(m.Cost.Output),
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].ProviderCode != out[j].ProviderCode {
			return out[i].ProviderCode < out[j].ProviderCode
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

// formatPerTokenPrice converts a models.dev per-million-token price into a
// per-token decimal string. Zero or negative values yield an empty string so
// the catalog stores no misleading "0" price.
func formatPerTokenPrice(perMillion float64) string {
	if perMillion <= 0 {
		return ""
	}
	return strconv.FormatFloat(perMillion/tokensPerPriceUnit, 'f', -1, 64)
}
