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
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// TestConnection probes the resource's deployments listing, the same request
// the model picker depends on. It does not exercise the registry's api_version:
// inference is the only route that reads it.
func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageConnectivity,
			Message: "azure endpoint is required",
		}
	}

	deploymentsURL, _, err := deploymentsListURL(config)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	result := c.probe(ctx, config, providers.AzureAPIDeployments, deploymentsURL)
	if result.StatusCode != http.StatusNotFound {
		return result
	}
	// A gateway in front of the resource (API Management, a private proxy) may
	// expose only the v1 surface. The listing still needs the deployments
	// route, but reachability and credentials can be proven without it.
	modelsURL := azureConfiguredEndpoint(config.Credentials.Azure.Endpoint) + "/openai/v1/models"
	return c.probe(ctx, config, providers.AzureAPIOpenAIV1, modelsURL)
}

func (c *client) probe(ctx context.Context, config *providers.Config, api, target string) providers.ProbeResult {
	auth, err := c.resolveAuthForAPI(ctx, config, api)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageAuthentication,
			Message: err.Error(),
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	auth.apply(req)
	return providers.RunHTTPProbe(providers.ProviderAzure, req)
}

// deploymentsListURL is where a resource lists its own deployments, whichever
// API surface the registry routes inference through: the deployment name is
// the model every surface sends. Azure serves this route only on
// deploymentsListAPIVersion and older, so the registry's api_version cannot be
// used here, and /openai/v1/models is no substitute because it lists every
// model the region offers rather than what this resource deployed. It also
// returns the registry's API surface.
func deploymentsListURL(config *providers.Config) (string, string, error) {
	opts, err := providers.DecodeAzureOptions(config.Options)
	if err != nil {
		return "", "", err
	}
	endpoint := azureRESTEndpoint(config.Credentials.Azure.Endpoint)
	return endpoint + "/openai/deployments?api-version=" + deploymentsListAPIVersion, opts.API, nil
}
