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

package modelallowlist

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

type behavior string

const (
	behaviorReject     behavior = "reject"
	behaviorSubstitute behavior = "substitute"
)

type config struct {
	AllowedModels  []string `mapstructure:"allowed_models"`
	DefaultModel   string   `mapstructure:"default_model"`
	Behavior       behavior `mapstructure:"behavior_on_disallowed"`
	SubstituteWith string   `mapstructure:"substitute_with"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) applyDefaults() {
	if c.Behavior == "" {
		c.Behavior = behaviorReject
	}
}

func (c *config) validate() error {
	if len(c.AllowedModels) == 0 {
		return fmt.Errorf("model_allowlist: allowed_models must not be empty")
	}
	for _, p := range c.AllowedModels {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("model_allowlist: allowed_models entries must not be blank")
		}
	}
	switch c.Behavior {
	case behaviorReject, behaviorSubstitute:
	default:
		return fmt.Errorf("model_allowlist: behavior_on_disallowed must be reject or substitute")
	}
	if c.Behavior == behaviorSubstitute {
		if c.SubstituteWith == "" {
			return fmt.Errorf("model_allowlist: substitute_with is required when behavior_on_disallowed is substitute")
		}
		if _, ok := matchAny(c.SubstituteWith, c.AllowedModels); !ok {
			return fmt.Errorf("model_allowlist: substitute_with %q does not match allowed_models", c.SubstituteWith)
		}
	} else if c.SubstituteWith != "" {
		return fmt.Errorf("model_allowlist: substitute_with must not be set when behavior_on_disallowed is %q", c.Behavior)
	}
	if c.DefaultModel != "" {
		if _, ok := matchAny(c.DefaultModel, c.AllowedModels); !ok {
			return fmt.Errorf("model_allowlist: default_model %q does not match allowed_models", c.DefaultModel)
		}
	}
	return nil
}

func matchAny(model string, patterns []string) (string, bool) {
	for _, p := range patterns {
		if matchGlob(p, model) {
			return p, true
		}
	}
	return "", false
}

func matchGlob(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}
	last := parts[len(parts)-1]
	return strings.HasSuffix(s, last)
}
