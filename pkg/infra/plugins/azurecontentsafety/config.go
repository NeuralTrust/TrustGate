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

package azurecontentsafety

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	OutputTypeFourSeverityLevels  = "FourSeverityLevels"
	OutputTypeEightSeverityLevels = "EightSeverityLevels"

	SeverityFourMin  = 0
	SeverityFourMax  = 6
	SeverityEightMin = 0
	SeverityEightMax = 7

	ThresholdFourMin  = 2
	ThresholdEightMin = 1

	CategoryHate     = "Hate"
	CategoryViolence = "Violence"
	CategorySelfHarm = "SelfHarm"
	CategorySexual   = "Sexual"
)

var supportedCategories = []string{CategoryHate, CategoryViolence, CategorySelfHarm, CategorySexual}

type Settings struct {
	APIKey           string         `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
	Endpoint         string         `mapstructure:"endpoint"`
	OutputType       string         `mapstructure:"output_type"`
	Categories       []string       `mapstructure:"categories"`
	CategorySeverity map[string]int `mapstructure:"category_severity"`
	Message          string         `mapstructure:"message"`
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
	if s.OutputType == "" {
		s.OutputType = OutputTypeFourSeverityLevels
	}
	if len(s.Categories) == 0 {
		s.Categories = append([]string(nil), supportedCategories...)
	}
}

func (s *Settings) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return fmt.Errorf("azure_content_safety: api_key is required")
	}
	if strings.TrimSpace(s.Endpoint) == "" {
		return fmt.Errorf("azure_content_safety: endpoint is required")
	}
	parsed, err := url.Parse(s.Endpoint)
	if err != nil {
		return fmt.Errorf("azure_content_safety: endpoint is invalid: %w", err)
	}
	if !parsed.IsAbs() || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("azure_content_safety: endpoint must be an absolute http(s) url")
	}
	switch s.OutputType {
	case OutputTypeFourSeverityLevels, OutputTypeEightSeverityLevels:
	default:
		return fmt.Errorf("azure_content_safety: output_type must be one of FourSeverityLevels, EightSeverityLevels")
	}
	if len(s.Categories) == 0 {
		return fmt.Errorf("azure_content_safety: categories must not be empty")
	}
	for _, category := range s.Categories {
		if !isSupportedCategory(category) {
			return fmt.Errorf("azure_content_safety: unsupported category %q", category)
		}
	}
	if len(s.CategorySeverity) == 0 {
		return fmt.Errorf("azure_content_safety: category_severity is required")
	}
	minThreshold, maxThreshold := s.thresholdBounds()
	for category, severity := range s.CategorySeverity {
		if !isSupportedCategory(category) {
			return fmt.Errorf("azure_content_safety: unsupported category_severity key %q", category)
		}
		if severity < minThreshold || severity > maxThreshold {
			return fmt.Errorf("azure_content_safety: category_severity for %q must be in [%d,%d]", category, minThreshold, maxThreshold)
		}
		if s.OutputType == OutputTypeFourSeverityLevels && severity%2 != 0 {
			return fmt.Errorf("azure_content_safety: category_severity for %q must be one of 2, 4, 6", category)
		}
	}
	return nil
}

func (s Settings) severityBounds() (int, int) {
	if s.OutputType == OutputTypeEightSeverityLevels {
		return SeverityEightMin, SeverityEightMax
	}
	return SeverityFourMin, SeverityFourMax
}

func (s Settings) thresholdBounds() (int, int) {
	if s.OutputType == OutputTypeEightSeverityLevels {
		return ThresholdEightMin, SeverityEightMax
	}
	return ThresholdFourMin, SeverityFourMax
}

func (s Settings) thresholdFor(category string) int {
	return s.CategorySeverity[category]
}

// requestCategories is the set of categories Execute asks Azure to analyze:
// Categories plus every category_severity key, so a thresholded category is
// always requested even on a policy saved before ValidateSettingsWrite
// started rejecting that gap. Deterministic order (Categories first, then
// the extra threshold keys sorted) keeps the outbound request stable across
// calls with the same settings.
func (s Settings) requestCategories() []string {
	seen := make(map[string]struct{}, len(s.Categories)+len(s.CategorySeverity))
	out := make([]string, 0, len(s.Categories)+len(s.CategorySeverity))
	for _, c := range s.Categories {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	extra := make([]string, 0, len(s.CategorySeverity))
	for c := range s.CategorySeverity {
		if _, ok := seen[c]; ok {
			continue
		}
		extra = append(extra, c)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// unrequestedThresholds returns, in deterministic (sorted) order, every
// category_severity key that categories does not name. Shared by
// ValidateSettingsWrite (rejects it at save time) so the two check exactly
// the same gap.
func (s Settings) unrequestedThresholds() []string {
	requested := make(map[string]struct{}, len(s.Categories))
	for _, c := range s.Categories {
		requested[c] = struct{}{}
	}
	var missing []string
	for c := range s.CategorySeverity {
		if _, ok := requested[c]; !ok {
			missing = append(missing, c)
		}
	}
	sort.Strings(missing)
	return missing
}

func isSupportedCategory(category string) bool {
	for _, supported := range supportedCategories {
		if supported == category {
			return true
		}
	}
	return false
}

// RetiredSettings lists the settings keys this policy never stores: the plugin
// ignores them, so a stored value would read as behaviour the policy does not
// have.
func (p *Plugin) RetiredSettings() []string {
	return []string{
		pluginutil.SettingOnError,
	}
}
