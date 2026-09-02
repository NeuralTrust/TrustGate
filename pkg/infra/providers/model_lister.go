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

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// LiveModel is one model id a provider reports as available to the supplied
// credentials — the ground truth the static catalog cannot see (org-restricted
// API keys, Azure deployments, account-gated models).
type LiveModel struct {
	ID          string
	DisplayName string
}

// ModelLister lists the models a provider's API reports as available to the
// given credentials. Provider clients implement it opportunistically — most
// reuse the same authenticated models endpoint their ConnectionTester probes,
// keeping the body the probe throws away.
type ModelLister interface {
	ListLiveModels(ctx context.Context, config *Config) ([]LiveModel, error)
}

// ErrModelListingFailed wraps any transport or provider failure during a live
// model listing so callers can degrade to the static catalog.
var ErrModelListingFailed = errors.New("live model listing failed")

// maxModelListBody bounds how much of a models response is read; the largest
// real listing (OpenRouter) is well under this.
const maxModelListBody = 8 << 20 // 8 MiB

// FetchModelListBody executes an authenticated GET against a provider's models
// endpoint and returns the raw body. Non-2xx statuses are errors: a live
// listing that cannot be trusted must fall back to the catalog, never narrow it.
func FetchModelListBody(providerKey string, req *http.Request) ([]byte, error) {
	client := probePool.Get(providerKey+"-models", ProbeHTTPTimeout)
	resp, err := client.Do(req) // #nosec G704 -- URL is built by the provider wrapper, not user input
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrModelListingFailed, err.Error())
	}
	defer DrainBody(resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: provider returned status %d", ErrModelListingFailed, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxModelListBody))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %s", ErrModelListingFailed, err.Error())
	}
	return body, nil
}

// ListModelsGET builds and executes a GET request with the provider's own
// header scheme and parses the body with parse.
func ListModelsGET(
	ctx context.Context,
	providerKey string,
	url string,
	applyHeaders func(*http.Request),
	parse func([]byte) ([]LiveModel, error),
) ([]LiveModel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrModelListingFailed, err.Error())
	}
	if applyHeaders != nil {
		applyHeaders(req)
	}
	body, err := FetchModelListBody(providerKey, req)
	if err != nil {
		return nil, err
	}
	return parse(body)
}

// ListBearerModelsGET is ListModelsGET for the common `Authorization: Bearer`
// + OpenAI-style listing shared by most providers.
func ListBearerModelsGET(ctx context.Context, providerKey, url, apiKey string) ([]LiveModel, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("%w: api key is required", ErrModelListingFailed)
	}
	return ListModelsGET(ctx, providerKey, url, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}, ParseOpenAIModelList)
}

// ParseOpenAIModelList decodes the `{"data":[{"id": ...}]}` listing used by
// OpenAI and every OpenAI-compatible provider; Anthropic's listing shares the
// envelope with `display_name`, OpenRouter's with `name`.
func ParseOpenAIModelList(body []byte) ([]LiveModel, error) {
	var payload struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			Name        string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode listing: %s", ErrModelListingFailed, err.Error())
	}
	models := make([]LiveModel, 0, len(payload.Data))
	for _, item := range payload.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		display := strings.TrimSpace(item.DisplayName)
		if display == "" {
			display = strings.TrimSpace(item.Name)
		}
		models = append(models, LiveModel{ID: id, DisplayName: display})
	}
	return models, nil
}
