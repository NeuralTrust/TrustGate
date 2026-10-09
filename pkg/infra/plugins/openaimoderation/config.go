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
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const PluginName = "openai_moderation"

const (
	defaultModel = ModelOmniLatest

	stagePreRequest  = "pre_request"
	stagePreResponse = "pre_response"
)

// Streaming defaults. The moderation endpoint is a single classifier call with
// no token leg in front of it, so it answers faster than a full guard and a
// tighter cadence is affordable: blocks close about twice as often as
// trustguard's, which buys a smaller window between the text being produced and
// being cleared.
//
// MaxAccumulatedBytes stays at 256 KiB: OpenAI documents no input size limit
// for the moderations endpoint, so there is nothing authoritative to fit to.
var streamingDefaults = pluginutil.StreamingDefaults{
	HeadChars:            400,
	MinCharsBetweenEvals: 1024,
	MaxHoldMS:            500,
	MaxAccumulatedBytes:  262144,
	GuardTimeout:         1500 * time.Millisecond,
}

type Settings struct {
	APIKey         string             `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
	Model          string             `mapstructure:"model"`
	Stages         []string           `mapstructure:"stages"`
	Categories     []string           `mapstructure:"categories"`
	Thresholds     map[string]float64 `mapstructure:"thresholds"`
	BlockOnFlagged bool               `mapstructure:"block_on_flagged"`
	Action         ActionSettings     `mapstructure:"action"`
	// OnError decides what a request gets when the guardrail cannot give a
	// verdict on its buffered leg: fail_open (the default) lets it through and
	// records failed_open, fail_closed refuses it in a mode that blocks.
	OnError string `mapstructure:"on_error"`
	// Streaming tunes the per-block inspection of the pre_response leg.
	Streaming pluginutil.StreamingSettings `mapstructure:"streaming"`
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
	// With no thresholds, evaluate() can only raise a violation through
	// BlockOnFlagged. A console-created policy omits both, so it would call
	// OpenAI and never block or report; the flagged verdict decides instead.
	// An explicit block_on_flagged is kept as sent.
	if v, set := settings["block_on_flagged"]; (!set || v == nil) && len(cfg.Thresholds) == 0 {
		cfg.BlockOnFlagged = true
	}
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	return cfg, nil
}

func (s *Settings) applyDefaults() {
	s.OnError = pluginutil.DefaultOnError(s.OnError)
	if s.Model == "" {
		s.Model = defaultModel
	}
	if len(s.Stages) == 0 {
		s.Stages = []string{stagePreRequest, stagePreResponse}
	}
	// The stream leg fails open by default whatever the buffered leg does: an
	// endpoint outage must not cut a response the client is already reading.
	// An explicit streaming.on_error: fail_closed is still honoured, and in the
	// modes that do not block the executor never turns an error into a cut.
	s.Streaming.ApplyDefaults(streamingDefaults, pluginutil.StreamOnErrorFailOpen)
}

func (s *Settings) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return fmt.Errorf("openai_moderation: api_key is required")
	}
	if err := pluginutil.ValidateOnError(PluginName, s.OnError); err != nil {
		return err
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
	return s.Streaming.Validate(PluginName)
}

func (s Settings) selectsStage(stage policy.Stage) bool {
	for _, st := range s.Stages {
		if policy.Stage(st) == stage {
			return true
		}
	}
	return false
}

// unknownAgainstModel reports, for s's own Model, whether that model is
// unrecognised, plus this config's own thresholds/categories keys that model
// does not know about. Unlike ValidateSettingsWrite's check, it does not
// weigh a previous version of the settings: every stored gap is worth a
// load-time warning once, regardless of how it got there.
func (s Settings) unknownAgainstModel() (modelUnknown bool, thresholds, categories []string) {
	known, ok := categoriesForModel(s.Model)
	if !ok {
		return true, nil, nil
	}
	for cat := range s.Thresholds {
		if _, isKnown := known[cat]; !isKnown {
			thresholds = append(thresholds, cat)
		}
	}
	sort.Strings(thresholds)
	seen := make(map[string]struct{}, len(s.Categories))
	for _, cat := range s.Categories {
		if _, dup := seen[cat]; dup {
			continue
		}
		seen[cat] = struct{}{}
		if _, isKnown := known[cat]; !isKnown {
			categories = append(categories, cat)
		}
	}
	sort.Strings(categories)
	return false, thresholds, categories
}
