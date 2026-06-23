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
	minSeverity, maxSeverity := s.severityBounds()
	for category, severity := range s.CategorySeverity {
		if !isSupportedCategory(category) {
			return fmt.Errorf("azure_content_safety: unsupported category_severity key %q", category)
		}
		if severity < minSeverity || severity > maxSeverity {
			return fmt.Errorf("azure_content_safety: category_severity for %q must be in [%d,%d]", category, minSeverity, maxSeverity)
		}
		if s.OutputType == OutputTypeFourSeverityLevels && severity%2 != 0 {
			return fmt.Errorf("azure_content_safety: category_severity for %q must be one of 0, 2, 4, 6", category)
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

func (s Settings) thresholdFor(category string) int {
	return s.CategorySeverity[category]
}

func isSupportedCategory(category string) bool {
	for _, supported := range supportedCategories {
		if supported == category {
			return true
		}
	}
	return false
}
