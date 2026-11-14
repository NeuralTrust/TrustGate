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

package watsonx

import (
	"context"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// TestConnection mints an IAM token from the API key, then lists the region's
// models with it. It does not call a model: that would need a model name and
// would bill tokens.
func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	opts, err := providers.DecodeWatsonxOptions(config.Options)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}

	token, err := c.tokens.token(ctx, config.Credentials.ApiKey)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageAuthentication, Message: err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, specsURL(opts), nil)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return providers.RunHTTPProbe(providers.ProviderWatsonx, req)
}
