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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const anthropicModelPrefix = "claude"

func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return nil, misconfigured("azure endpoint is required")
	}
	targetURL, api, err := deploymentsListURL(config)
	if err != nil {
		return nil, misconfigured(err.Error())
	}
	auth, err := c.resolveAuth(ctx, config)
	if err != nil {
		return nil, misconfigured(err.Error())
	}
	models, err := providers.ListModelsGET(ctx, providers.ProviderAzure, targetURL, func(req *http.Request) {
		auth.apply(req)
	}, parseAzureDeploymentList)
	if err != nil {
		var status *providers.ModelListingStatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
			// A 404 here is either a wrong endpoint or Azure retiring the
			// pinned version; only the second one breaks every registry.
			slog.WarnContext(ctx, "azure deployments listing route not found",
				slog.String("api_version", deploymentsListAPIVersion))
		}
		return nil, err
	}
	return deploymentsForSurface(models, api), nil
}

func misconfigured(detail string) error {
	return fmt.Errorf("%w: %w: %s", providers.ErrModelListingFailed, providers.ErrModelListingMisconfigured, detail)
}

// deploymentsForSurface keeps the deployments the registry's API surface can
// call: Claude deployments answer only on the Anthropic surface, and every
// other model only on the OpenAI ones. A deployment that does not name its
// model is kept.
func deploymentsForSurface(models []providers.LiveModel, api string) []providers.LiveModel {
	wantAnthropic := api == providers.AzureAPIAnthropic
	kept := make([]providers.LiveModel, 0, len(models))
	for _, model := range models {
		if model.ProviderModel != "" &&
			strings.HasPrefix(strings.ToLower(model.ProviderModel), anthropicModelPrefix) != wantAnthropic {
			continue
		}
		kept = append(kept, model)
	}
	return kept
}

func parseAzureDeploymentList(body []byte) ([]providers.LiveModel, error) {
	var payload struct {
		Data []struct {
			ID     string `json:"id"`
			Model  string `json:"model"`
			Status string `json:"status"`
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
			Pending:       !deploymentServes(item.Status),
		})
	}
	return models, nil
}

// deploymentServes reports whether a deployment in this state accepts
// requests. A listing that omits the status is trusted as serving.
func deploymentServes(status string) bool {
	status = strings.TrimSpace(status)
	return status == "" || strings.EqualFold(status, "succeeded")
}
