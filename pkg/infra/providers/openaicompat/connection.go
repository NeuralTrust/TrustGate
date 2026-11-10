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

package openaicompat

import (
	"context"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const modelsPath = "/models"

// TestConnection probes the upstream with a GET to {base_url}/models, the
// de-facto discovery endpoint exposed by OpenAI-compatible servers. Authorization
// is set only when an API key is configured. Custom headers from auth and
// provider_options are applied afterwards, so an Authorization entry in that
// map replaces the bearer token.
func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageProvider,
			Message: err.Error(),
		}
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+modelsPath, nil)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	applyUpstreamAuth(req, config.Credentials.ApiKey, upstreamHeaders(config.Credentials, opts))
	return providers.RunHTTPProbe(providers.ProviderOpenAICompatible, req)
}
