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
// It is on by default: a guardrail that silently stops guarding the moment a
// client sets stream: true is not a guardrail. A policy opts out with
// streaming.enabled: false.
//
// Each block sends at most maxStreamWindowBytes of the accumulated text. OpenAI
// documents no input size limit for the moderations endpoint, so the window is
// fitted to the deadline instead: the classifier's latency grows with the text,
// and the 1.5 s a block waits is spent long before a quarter of a megabyte. It
// stays above 30 blocks of the default cadence, so the text that straddles two
// blocks is always inside the window.
var streamingDefaults = pluginutil.StreamingDefaults{
	EnabledByDefault:     true,
	HeadChars:            400,
	MinCharsBetweenEvals: 1024,
	MaxHoldMS:            500,
	MaxAccumulatedBytes:  maxStreamWindowBytes,
	GuardTimeout:         1500 * time.Millisecond,
}

const maxStreamWindowBytes = 32768

type Settings struct {
	APIKey         string             `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
	Model          string             `mapstructure:"model"`
	Stages         []string           `mapstructure:"stages"`
	Categories     []string           `mapstructure:"categories"`
	Thresholds     map[string]float64 `mapstructure:"thresholds"`
	BlockOnFlagged bool               `mapstructure:"block_on_flagged"`
	Action         ActionSettings     `mapstructure:"action"`
	// Streaming tunes the per-block inspection of the pre_response leg. It is on
	// when the block is absent; streaming.enabled: false opts out.
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
	if s.Model == "" {
		s.Model = defaultModel
	}
	if len(s.Stages) == 0 {
		s.Stages = []string{stagePreRequest, stagePreResponse}
	}
	s.Streaming.ApplyDefaults(streamingDefaults)
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

// RetiredSettings lists the settings keys this policy never stores: the plugin
// ignores them, so a stored value would read as behaviour the policy does not
// have.
func (p *Plugin) RetiredSettings() []string {
	return []string{
		pluginutil.SettingOnError,
		pluginutil.SettingStreamingOnError, pluginutil.SettingStreamingGuardTimeout,
	}
}
