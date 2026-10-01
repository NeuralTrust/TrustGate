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

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return nil, fmt.Errorf("%w: azure endpoint is required", providers.ErrModelListingFailed)
	}
	targetURL, api, err := c.buildModelsURL(config)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", providers.ErrModelListingFailed, err.Error())
	}
	auth, err := c.resolveAuthForAPI(ctx, config, api)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", providers.ErrModelListingFailed, err.Error())
	}
	parse := providers.ParseOpenAIModelList
	if api == providers.AzureAPIDeployments {
		parse = parseAzureDeploymentList
	}
	return providers.ListModelsGET(ctx, providers.ProviderAzure, targetURL, func(req *http.Request) {
		auth.apply(req)
	}, parse)
}

func parseAzureDeploymentList(body []byte) ([]providers.LiveModel, error) {
	var payload struct {
		Data []struct {
			ID    string `json:"id"`
			Model string `json:"model"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode deployments: %s", providers.ErrModelListingFailed, err.Error())
	}
	seen := make(map[string]struct{}, len(payload.Data))
	models := make([]providers.LiveModel, 0, len(payload.Data))
	for _, item := range payload.Data {
		deployment := strings.TrimSpace(item.ID)
		if deployment == "" {
			continue
		}
		if _, dup := seen[deployment]; dup {
			continue
		}
		seen[deployment] = struct{}{}
		models = append(models, providers.LiveModel{
			ID:            deployment,
			DisplayName:   deployment,
			ProviderModel: strings.TrimSpace(item.Model),
		})
	}
	return models, nil
}
