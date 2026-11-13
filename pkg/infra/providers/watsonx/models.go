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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	specsPath      = "/ml/v1/foundation_model_specs"
	chatFunction   = "text_chat"
	specsPageLimit = "200"

	lifecycleWithdrawn  = "withdrawn"
	lifecycleDeprecated = "deprecated"
)

type modelSpecs struct {
	Resources []modelSpec `json:"resources"`
}

type modelSpec struct {
	ModelID   string `json:"model_id"`
	Label     string `json:"label"`
	Functions []struct {
		ID string `json:"id"`
	} `json:"functions"`
	Lifecycle []struct {
		ID        string `json:"id"`
		StartDate string `json:"start_date"`
	} `json:"lifecycle"`
}

func specsURL(opts providers.WatsonxOptions) string {
	return endpointURL(opts, specsPath, url.Values{
		"filters": {"function_" + chatFunction},
		"limit":   {specsPageLimit},
	})
}

// ListLiveModels lists the chat models the registry's region serves. Regions
// differ: Frankfurt serves fewer models than Dallas.
func (c *client) ListLiveModels(ctx context.Context, config *providers.Config) ([]providers.LiveModel, error) {
	opts, err := providers.DecodeWatsonxOptions(config.Options)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %w", providers.ErrModelListingFailed, providers.ErrModelListingMisconfigured, err)
	}
	token, err := c.tokens.token(ctx, config.Credentials.ApiKey)
	if err != nil {
		if errors.Is(err, errIAMRejected) {
			return nil, fmt.Errorf("%w: %w: %w", providers.ErrModelListingFailed, providers.ErrModelListingMisconfigured, err)
		}
		return nil, fmt.Errorf("%w: %w", providers.ErrModelListingFailed, err)
	}
	return providers.ListModelsGET(ctx, providers.ProviderWatsonx, specsURL(opts), func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
	}, func(body []byte) ([]providers.LiveModel, error) {
		return parseModelSpecs(body, time.Now())
	})
}

func parseModelSpecs(body []byte, now time.Time) ([]providers.LiveModel, error) {
	var specs modelSpecs
	if err := json.Unmarshal(body, &specs); err != nil {
		return nil, fmt.Errorf("%w: decode watsonx model specs: %w", providers.ErrModelListingFailed, err)
	}
	today := now.UTC().Format(time.DateOnly)
	models := make([]providers.LiveModel, 0, len(specs.Resources))
	for _, spec := range specs.Resources {
		id := strings.TrimSpace(spec.ModelID)
		if id == "" || !spec.servesChat() || spec.reached(lifecycleWithdrawn, today) {
			continue
		}
		display := strings.TrimSpace(spec.Label)
		if display == "" {
			display = id
		}
		if spec.reached(lifecycleDeprecated, today) {
			display += " (deprecated)"
		}
		models = append(models, providers.LiveModel{ID: id, DisplayName: display, ProviderModel: id})
	}
	return models, nil
}

func (s modelSpec) servesChat() bool {
	for _, fn := range s.Functions {
		if fn.ID == chatFunction {
			return true
		}
	}
	return false
}

// reached reports whether the model entered lifecycle stage id on or before
// today. IBM publishes deprecation and withdrawal dates in advance.
func (s modelSpec) reached(id, today string) bool {
	for _, stage := range s.Lifecycle {
		if stage.ID == id && stage.StartDate != "" && stage.StartDate <= today {
			return true
		}
	}
	return false
}
