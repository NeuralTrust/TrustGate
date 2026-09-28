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
	"fmt"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageConnectivity,
			Message: "azure endpoint is required",
		}
	}

	modelsURL, api, err := c.buildModelsURL(config)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	auth, err := c.resolveAuthForAPI(ctx, config, api)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageAuthentication,
			Message: err.Error(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	auth.apply(req)
	return providers.RunHTTPProbe(providers.ProviderAzure, req)
}

func (c *client) buildModelsURL(config *providers.Config) (string, string, error) {
	opts, err := providers.DecodeAzureOptions(config.Options)
	if err != nil {
		return "", "", err
	}
	configuredEndpoint := azureConfiguredEndpoint(config.Credentials.Azure.Endpoint)
	// Foundry documents model discovery through the shared OpenAI v1 surface,
	// including on services.ai.azure.com endpoints. The native Anthropic
	// surface only documents inference endpoints such as /messages.
	switch opts.API {
	case providers.AzureAPIOpenAIV1, providers.AzureAPIResponses:
		return configuredEndpoint + "/openai/v1/models", opts.API, nil
	case providers.AzureAPIAnthropic:
		return configuredEndpoint + "/openai/v1/models", providers.AzureAPIOpenAIV1, nil
	}
	endpoint := azureRESTEndpoint(config.Credentials.Azure.Endpoint)
	apiVersion := defaultAPIVersion
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}
	return fmt.Sprintf("%s/openai/deployments?api-version=%s", endpoint, apiVersion), opts.API, nil
}
