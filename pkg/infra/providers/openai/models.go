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

package openai

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// ListLiveModels lists the models this API key can use. Project-scoped keys
// with a model allow-list only return the allowed models, which is exactly
// the availability the static catalog cannot know.
func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	url, err := c.resolveModelsURL(config)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", providers.ErrModelListingFailed, err.Error())
	}
	return providers.ListBearerModelsGET(ctx, providers.ProviderOpenAI, url, config.Credentials.ApiKey)
}
