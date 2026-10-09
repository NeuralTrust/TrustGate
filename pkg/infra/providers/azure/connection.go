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

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageConnectivity,
			Message: "azure endpoint is required",
		}
	}

	deploymentsURL, err := deploymentsListURL(config)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	auth, err := c.resolveAuth(ctx, config)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageAuthentication,
			Message: err.Error(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deploymentsURL, nil)
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
// model the region offers rather than what this resource deployed (RUN-1144).
func deploymentsListURL(config *providers.Config) (string, error) {
	if _, err := providers.DecodeAzureOptions(config.Options); err != nil {
		return "", err
	}
	endpoint := azureRESTEndpoint(config.Credentials.Azure.Endpoint)
	return endpoint + "/openai/deployments?api-version=" + deploymentsListAPIVersion, nil
}
