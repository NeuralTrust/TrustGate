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

package anthropic

import (
	"context"
	"fmt"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// One page covers Anthropic's whole listing (a few dozen models); the API caps
// limit at 1000.
const modelsPageLimit = 1000

// ListLiveModels lists the models this API key can use from the same endpoint
// the connection probe hits; workspace-restricted keys only return what they
// may invoke.
func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("%w: api key is required", providers.ErrModelListingFailed)
	}
	url := fmt.Sprintf("%s?limit=%d", modelsURL, modelsPageLimit)
	return providers.ListModelsGET(ctx, providers.ProviderAnthropic, url, func(req *http.Request) {
		c.setHeaders(req, config.Credentials.ApiKey)
	}, providers.ParseOpenAIModelList)
}
