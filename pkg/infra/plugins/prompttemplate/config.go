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

package prompttemplate

import (
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

type engine string

const (
	engineMustache engine = "mustache"
	engineJinja2   engine = "jinja2_subset"
)

type onMissingContext string

const (
	onMissingContextError       onMissingContext = "error"
	onMissingContextEmptyString onMissingContext = "empty_string"
	onMissingContextSkip        onMissingContext = "skip_injection"
)

type onMissingClient string

const (
	onMissingClientError       onMissingClient = "error"
	onMissingClientEmptyString onMissingClient = "empty_string"
)

type onExistingSystem string

const (
	onExistingMerge   onExistingSystem = "merge"
	onExistingReplace onExistingSystem = "replace"
)

type varSource string

const (
	sourceHeader   varSource = "header"
	sourceJWTClaim varSource = "jwt_claim"
)

type contextVar struct {
	Source varSource `mapstructure:"source"`
	Name   string    `mapstructure:"name"`
}

type injectTemplate struct {
	ID               string           `mapstructure:"id"`
	Position         string           `mapstructure:"position"`
	Role             string           `mapstructure:"role"`
	Content          string           `mapstructure:"content"`
	OnExistingSystem onExistingSystem `mapstructure:"on_existing_system"`
}

type requiredVar struct {
	Type      string   `mapstructure:"type"`
	Enum      []string `mapstructure:"enum"`
	MaxLength int      `mapstructure:"max_length"`
}

type templateVersion struct {
	Version           string                 `mapstructure:"version"`
	Labels            []string               `mapstructure:"labels"`
	Content           string                 `mapstructure:"content"`
	RequiredVariables map[string]requiredVar `mapstructure:"required_variables"`
}

type namedTemplate struct {
	Name     string            `mapstructure:"name"`
	Versions []templateVersion `mapstructure:"versions"`
}

type config struct {
	TemplateEngine           engine                `mapstructure:"template_engine"`
	ContextVariables         map[string]contextVar `mapstructure:"context_variables"`
	InjectTemplates          []injectTemplate      `mapstructure:"inject_templates"`
	NamedTemplates           []namedTemplate       `mapstructure:"named_templates"`
	AllowUntemplatedRequests bool                  `mapstructure:"allow_untemplated_requests"`
	OnMissingContextVariable onMissingContext      `mapstructure:"on_missing_context_variable"`
	OnMissingClientVariable  onMissingClient       `mapstructure:"on_missing_client_variable"`
	DefaultLabel             string                `mapstructure:"default_label"`
	EscapeJSONControlChars   *bool                 `mapstructure:"escape_json_control_chars"`
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
	if c.TemplateEngine == "" {
		c.TemplateEngine = engineMustache
	}
	if c.OnMissingContextVariable == "" {
		c.OnMissingContextVariable = onMissingContextError
	}
	if c.OnMissingClientVariable == "" {
		c.OnMissingClientVariable = onMissingClientError
	}
	for i := range c.InjectTemplates {
		if c.InjectTemplates[i].Position == "" {
			c.InjectTemplates[i].Position = "system"
		}
		if c.InjectTemplates[i].Role == "" {
			c.InjectTemplates[i].Role = "system"
		}
		if c.InjectTemplates[i].OnExistingSystem == "" {
			c.InjectTemplates[i].OnExistingSystem = onExistingMerge
		}
	}
	if c.EscapeJSONControlChars == nil {
		enabled := true
		c.EscapeJSONControlChars = &enabled
	}
}

func (c *config) validate() error {
	return nil
}
