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
	"fmt"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// ListLiveModels lists the models the configured OpenAI-compatible server
// exposes — `GET {base}/models` is part of the compatibility contract.
func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", providers.ErrModelListingFailed, err.Error())
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	return providers.ListModelsGET(ctx, providers.ProviderOpenAICompatible, base+modelsPath, func(req *http.Request) {
		if config.Credentials.ApiKey != "" {
			req.Header.Set("Authorization", "Bearer "+config.Credentials.ApiKey)
		}
		for k, v := range opts.Headers {
			if k == "" {
				continue
			}
			req.Header.Set(k, v)
		}
	}, providers.ParseOpenAIModelList)
}
