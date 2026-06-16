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

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const modelsPath = "/models"

// TestConnection probes the upstream with a Bearer GET to {base_url}/models,
// the de-facto discovery endpoint exposed by OpenAI-compatible servers. Any
// configured custom headers are applied to the probe as well.
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
	return providers.RunAPIKeyGETProbe(
		ctx,
		providers.ProviderOpenAICompatible,
		base+modelsPath,
		config.Credentials.ApiKey,
		func(req *http.Request, key string) {
			req.Header.Set("Authorization", "Bearer "+key)
			for k, v := range opts.Headers {
				if k == "" {
					continue
				}
				req.Header.Set(k, v)
			}
		},
	)
}
