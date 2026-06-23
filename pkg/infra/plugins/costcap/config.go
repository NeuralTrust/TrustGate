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

package costcap

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

type config struct {
	Cap           llmcost.CapConfig              `mapstructure:",squash"`
	CustomPricing map[string]llmcost.CustomPrice `mapstructure:"custom_pricing"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	cfg.Cap.Enabled = true
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if err := c.Cap.Validate(); err != nil {
		return err
	}
	if c.Cap.MaxInputCostPer1k <= 0 && c.Cap.MaxOutputCostPer1k <= 0 && !hasOverrideCeiling(c.Cap) {
		return fmt.Errorf("cost_cap: set at least one of max_input_cost_per_1k_tokens, max_output_cost_per_1k_tokens, or per_model_overrides")
	}
	return nil
}

func hasOverrideCeiling(capCfg llmcost.CapConfig) bool {
	for k := range capCfg.PerModelOverrides {
		ceiling := capCfg.PerModelOverrides[k]
		if ceiling.MaxInputCostPer1k > 0 || ceiling.MaxOutputCostPer1k > 0 {
			return true
		}
	}
	return false
}
