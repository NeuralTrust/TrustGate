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

// ListLiveModels lists what this Azure resource can actually serve: its
// deployments. Requests are routed by deployment name, so both the deployment
// id and its underlying model name are reported as live ids — the catalog's
// model slugs match through the latter.
func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return nil, fmt.Errorf("%w: azure endpoint is required", providers.ErrModelListingFailed)
	}
	auth, err := c.resolveAuth(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", providers.ErrModelListingFailed, err.Error())
	}
	return providers.ListModelsGET(ctx, providers.ProviderAzure, c.buildDeploymentsURL(config), func(req *http.Request) {
		auth.apply(req)
	}, parseAzureDeploymentList)
}

func (c *client) buildDeploymentsURL(config *providers.Config) string {
	endpoint := azureRESTEndpoint(config.Credentials.Azure.Endpoint)
	apiVersion := defaultAPIVersion
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}
	return fmt.Sprintf("%s/openai/deployments?api-version=%s", endpoint, apiVersion)
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
	seen := make(map[string]struct{}, len(payload.Data)*2)
	models := make([]providers.LiveModel, 0, len(payload.Data)*2)
	add := func(id, display string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		models = append(models, providers.LiveModel{ID: id, DisplayName: display})
	}
	for _, item := range payload.Data {
		add(item.ID, item.ID)
		add(item.Model, "")
	}
	return models, nil
}
