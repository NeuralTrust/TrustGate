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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	modelsURL  = "https://api.openai.com/v1/models"
	modelsPath = "/models"
)

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	endpointURL, err := c.resolveModelsURL(config)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageProvider,
			Message: err.Error(),
		}
	}
	return providers.RunBearerGETProbe(ctx, providers.ProviderOpenAI, endpointURL, config.Credentials.ApiKey)
}

func (c *client) resolveModelsURL(config *providers.Config) (string, error) {
	opts, err := providers.DecodeOpenAIOptions(config.Options)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	if base != "" {
		return base + modelsPath, nil
	}
	return modelsURL, nil
}
