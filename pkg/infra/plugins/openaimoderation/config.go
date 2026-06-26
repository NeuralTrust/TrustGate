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

package openaimoderation

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const PluginName = "openai_moderation"

const (
	defaultModel = "omni-moderation-latest"

	stagePreRequest  = "pre_request"
	stagePreResponse = "pre_response"
)

type Settings struct {
	APIKey         string             `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
	Model          string             `mapstructure:"model"`
	Stages         []string           `mapstructure:"stages"`
	Categories     []string           `mapstructure:"categories"`
	Thresholds     map[string]float64 `mapstructure:"thresholds"`
	BlockOnFlagged bool               `mapstructure:"block_on_flagged"`
	Action         ActionSettings     `mapstructure:"action"`
}

type ActionSettings struct {
	Message string `mapstructure:"message"`
}

func parseConfig(settings map[string]any) (Settings, error) {
	cfg, err := pluginutil.Parse[Settings](settings)
	if err != nil {
		return Settings{}, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	return cfg, nil
}

func (s *Settings) applyDefaults() {
	if s.Model == "" {
		s.Model = defaultModel
	}
	if len(s.Stages) == 0 {
		s.Stages = []string{stagePreRequest, stagePreResponse}
	}
}

func (s *Settings) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return fmt.Errorf("openai_moderation: api_key is required")
	}
	for _, stage := range s.Stages {
		if stage != stagePreRequest && stage != stagePreResponse {
			return fmt.Errorf("openai_moderation: stages must be pre_request or pre_response")
		}
	}
	for cat, value := range s.Thresholds {
		if value < 0 || value > 1 {
			return fmt.Errorf("openai_moderation: threshold for %q must be between 0 and 1", cat)
		}
	}
	return nil
}

func (s Settings) selectsStage(stage policy.Stage) bool {
	for _, st := range s.Stages {
		if policy.Stage(st) == stage {
			return true
		}
	}
	return false
}
