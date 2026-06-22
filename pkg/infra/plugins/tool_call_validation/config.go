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

package tool_call_validation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	validatorNotInAllowedList = "not_in_allowed_list"
	validatorJSONSchema       = "json_schema"
	validatorSemantic         = "semantic"
	validatorRegex            = "regex"
	validatorDenylist         = "denylist"

	behaviorReject      = "reject_response"
	behaviorRedact      = "redact"
	behaviorMask        = "mask"
	behaviorReplaceWith = "replace_with"

	semanticProviderOpenAI = "openai"
	defaultSemanticModel   = "gpt-4o-mini"
	defaultMask            = "****"
	defaultRedactionMarker = "[REDACTED]"
)

type Config struct {
	Scope    string          `mapstructure:"scope"`
	Semantic *SemanticConfig `mapstructure:"semantic"`
	Rules    []RuleConfig    `mapstructure:"rules"`
}

type SemanticConfig struct {
	Provider string `mapstructure:"provider"`
	APIKey   string `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
	Model    string `mapstructure:"model"`
}

type RuleConfig struct {
	Tool         string   `mapstructure:"tool"`
	Validator    string   `mapstructure:"validator"`
	ArgumentPath string   `mapstructure:"argument_path"`
	Pattern      string   `mapstructure:"pattern"`
	Denylist     []string `mapstructure:"denylist"`
	Behavior     string   `mapstructure:"behavior"`
	RedactWith   string   `mapstructure:"redact_with"`
}

func parseConfig(settings map[string]any) (*Config, error) {
	cfg, err := pluginutil.Parse[Config](settings)
	if err != nil {
		return nil, fmt.Errorf("tool_call_validation: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.Behavior == "" {
			rule.Behavior = behaviorReject
		}
		switch rule.Behavior {
		case behaviorRedact:
			if rule.RedactWith == "" {
				rule.RedactWith = defaultRedactionMarker
			}
		case behaviorMask:
			if rule.RedactWith == "" {
				rule.RedactWith = defaultMask
			}
		}
	}
	if c.Semantic != nil {
		if c.Semantic.Provider == "" {
			c.Semantic.Provider = semanticProviderOpenAI
		}
		if c.Semantic.Model == "" {
			c.Semantic.Model = defaultSemanticModel
		}
	}
}

func (c *Config) validate() error {
	if len(c.Rules) == 0 {
		return fmt.Errorf("tool_call_validation: at least one rule is required")
	}
	needsSemantic := false
	for i := range c.Rules {
		rule := c.Rules[i]
		if !isKnownValidator(rule.Validator) {
			return fmt.Errorf("tool_call_validation: rule %d has unknown validator %q", i, rule.Validator)
		}
		if !isKnownBehavior(rule.Behavior) {
			return fmt.Errorf("tool_call_validation: rule %d has unknown behavior %q", i, rule.Behavior)
		}
		if isRedactionBehavior(rule.Behavior) && !isArgumentValidator(rule.Validator) {
			return fmt.Errorf("tool_call_validation: rule %d behavior %q is only allowed for %q or %q validators", i, rule.Behavior, validatorRegex, validatorDenylist)
		}
		switch rule.Validator {
		case validatorRegex:
			if rule.Pattern == "" {
				return fmt.Errorf("tool_call_validation: rule %d (regex) requires a non-empty pattern", i)
			}
			if rule.ArgumentPath == "" {
				return fmt.Errorf("tool_call_validation: rule %d (regex) requires a non-empty argument_path", i)
			}
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("tool_call_validation: rule %d (regex) pattern does not compile: %w", i, err)
			}
			if err := validateArgumentPath(i, rule.ArgumentPath); err != nil {
				return err
			}
		case validatorDenylist:
			if len(rule.Denylist) == 0 {
				return fmt.Errorf("tool_call_validation: rule %d (denylist) requires a non-empty denylist", i)
			}
			if rule.ArgumentPath == "" {
				return fmt.Errorf("tool_call_validation: rule %d (denylist) requires a non-empty argument_path", i)
			}
			if err := validateArgumentPath(i, rule.ArgumentPath); err != nil {
				return err
			}
		case validatorNotInAllowedList, validatorJSONSchema, validatorSemantic:
			if rule.ArgumentPath != "" {
				return fmt.Errorf("tool_call_validation: rule %d (%s) must not set argument_path", i, rule.Validator)
			}
			if rule.Behavior != behaviorReject {
				return fmt.Errorf("tool_call_validation: rule %d (%s) only supports behavior %q", i, rule.Validator, behaviorReject)
			}
		}
		if rule.Behavior == behaviorReplaceWith && rule.RedactWith == "" {
			return fmt.Errorf("tool_call_validation: rule %d (replace_with) requires a non-empty redact_with", i)
		}
		if rule.Validator == validatorSemantic {
			needsSemantic = true
		}
	}
	return c.validateSemantic(needsSemantic)
}

func (c *Config) validateSemantic(needsSemantic bool) error {
	if needsSemantic && c.Semantic == nil {
		return fmt.Errorf("tool_call_validation: a semantic rule requires a semantic block with provider and api_key")
	}
	if c.Semantic == nil {
		return nil
	}
	if c.Semantic.Provider != "" && c.Semantic.Provider != semanticProviderOpenAI {
		return fmt.Errorf("tool_call_validation: semantic provider %q is not supported (only %q)", c.Semantic.Provider, semanticProviderOpenAI)
	}
	if c.Semantic.Provider == semanticProviderOpenAI && c.Semantic.APIKey == "" {
		return fmt.Errorf("tool_call_validation: semantic.api_key is required when provider is %q", semanticProviderOpenAI)
	}
	return nil
}

func validateArgumentPath(index int, path string) error {
	if !strings.HasPrefix(path, "$") {
		return fmt.Errorf("tool_call_validation: rule %d argument_path %q must be a JSONPath beginning with '$'", index, path)
	}
	return nil
}

func isKnownValidator(name string) bool {
	switch name {
	case validatorNotInAllowedList, validatorJSONSchema, validatorSemantic, validatorRegex, validatorDenylist:
		return true
	default:
		return false
	}
}

func isKnownBehavior(name string) bool {
	switch name {
	case behaviorReject, behaviorRedact, behaviorMask, behaviorReplaceWith:
		return true
	default:
		return false
	}
}

func isArgumentValidator(name string) bool {
	return name == validatorRegex || name == validatorDenylist
}

func isRedactionBehavior(name string) bool {
	return name == behaviorRedact || name == behaviorMask || name == behaviorReplaceWith
}
