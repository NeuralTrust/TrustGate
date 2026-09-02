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

package cohere

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// One page covers Cohere's whole listing; the API caps page_size at 1000.
const modelsPageSize = 1000

// ListLiveModels lists the models this API key can use from the same endpoint
// the connection probe hits.
func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("%w: api key is required", providers.ErrModelListingFailed)
	}
	url, err := modelsURL(config.Options)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", providers.ErrModelListingFailed, err.Error())
	}
	url = fmt.Sprintf("%s?page_size=%d", url, modelsPageSize)
	return providers.ListModelsGET(ctx, providers.ProviderCohere, url, func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+config.Credentials.ApiKey)
	}, parseCohereModelList)
}

func parseCohereModelList(body []byte) ([]providers.LiveModel, error) {
	var payload struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode listing: %s", providers.ErrModelListingFailed, err.Error())
	}
	models := make([]providers.LiveModel, 0, len(payload.Models))
	for _, item := range payload.Models {
		id := strings.TrimSpace(item.Name)
		if id == "" {
			continue
		}
		models = append(models, providers.LiveModel{ID: id})
	}
	return models, nil
}
