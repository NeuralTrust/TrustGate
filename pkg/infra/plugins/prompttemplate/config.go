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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

var (
	placeholderScanRe = regexp.MustCompile(`\{\{([^{}]*)\}\}`)
	placeholderNameRe = regexp.MustCompile(`^[\w.-]+$`)
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
	switch c.TemplateEngine {
	case engineMustache:
	case engineJinja2:
		return fmt.Errorf("prompt_template: template_engine %q is not yet supported (v1 supports mustache only)", c.TemplateEngine)
	default:
		return fmt.Errorf("prompt_template: template_engine %q is not supported", c.TemplateEngine)
	}

	switch c.OnMissingContextVariable {
	case onMissingContextError, onMissingContextEmptyString, onMissingContextSkip:
	default:
		return fmt.Errorf("prompt_template: on_missing_context_variable %q must be error, empty_string, or skip_injection", c.OnMissingContextVariable)
	}

	switch c.OnMissingClientVariable {
	case onMissingClientError, onMissingClientEmptyString:
	default:
		return fmt.Errorf("prompt_template: on_missing_client_variable %q must be error or empty_string", c.OnMissingClientVariable)
	}

	if err := c.validateContextVariables(); err != nil {
		return err
	}

	if len(c.InjectTemplates) == 0 && len(c.NamedTemplates) == 0 {
		return fmt.Errorf("prompt_template: at least one of inject_templates or named_templates must be set")
	}

	if err := c.validateInjectTemplates(); err != nil {
		return err
	}
	return c.validateNamedTemplates()
}

func (c *config) validateContextVariables() error {
	for key, cv := range c.ContextVariables {
		switch cv.Source {
		case sourceHeader, sourceJWTClaim:
		case "consumer_attribute":
			return fmt.Errorf("prompt_template: context_variables[%q].source consumer_attribute is deferred/unsupported in v1", key)
		default:
			return fmt.Errorf("prompt_template: context_variables[%q].source %q must be header or jwt_claim", key, cv.Source)
		}
		if strings.TrimSpace(cv.Name) == "" {
			return fmt.Errorf("prompt_template: context_variables[%q].name must not be blank", key)
		}
	}
	return nil
}

func (c *config) validateInjectTemplates() error {
	for i := range c.InjectTemplates {
		it := c.InjectTemplates[i]
		if strings.TrimSpace(it.ID) == "" {
			return fmt.Errorf("prompt_template: inject_templates[%d].id must not be blank", i)
		}
		if strings.TrimSpace(it.Content) == "" {
			return fmt.Errorf("prompt_template: inject_templates[%d].content must not be blank", i)
		}
		if it.Position != "system" {
			return fmt.Errorf("prompt_template: inject_templates[%d].position %q must be system", i, it.Position)
		}
		if strings.TrimSpace(it.Role) == "" {
			return fmt.Errorf("prompt_template: inject_templates[%d].role must not be blank", i)
		}
		switch it.OnExistingSystem {
		case onExistingMerge, onExistingReplace:
		default:
			return fmt.Errorf("prompt_template: inject_templates[%d].on_existing_system %q must be merge or replace", i, it.OnExistingSystem)
		}
		if err := validatePlaceholders(it.Content); err != nil {
			return fmt.Errorf("prompt_template: inject_templates[%d].content: %w", i, err)
		}
	}
	return nil
}

func (c *config) validateNamedTemplates() error {
	labels := map[string]struct{}{}
	names := map[string]struct{}{}
	for i := range c.NamedTemplates {
		nt := c.NamedTemplates[i]
		if strings.TrimSpace(nt.Name) == "" {
			return fmt.Errorf("prompt_template: named_templates[%d].name must not be blank", i)
		}
		if _, dup := names[nt.Name]; dup {
			return fmt.Errorf("prompt_template: named_templates name %q is duplicated", nt.Name)
		}
		names[nt.Name] = struct{}{}
		if len(nt.Versions) == 0 {
			return fmt.Errorf("prompt_template: named_templates[%q] must have at least one version", nt.Name)
		}
		if err := validateVersions(nt, labels); err != nil {
			return err
		}
	}
	if len(c.NamedTemplates) > 0 && c.DefaultLabel != "" {
		if _, ok := labels[c.DefaultLabel]; !ok {
			return fmt.Errorf("prompt_template: default_label %q does not match any version label", c.DefaultLabel)
		}
	}
	return nil
}

func validateVersions(nt namedTemplate, labels map[string]struct{}) error {
	for j := range nt.Versions {
		v := nt.Versions[j]
		if len(v.Labels) == 0 {
			return fmt.Errorf("prompt_template: named_templates[%q].versions[%d] must have at least one label", nt.Name, j)
		}
		for _, label := range v.Labels {
			if strings.TrimSpace(label) == "" {
				return fmt.Errorf("prompt_template: named_templates[%q].versions[%d] has a blank label", nt.Name, j)
			}
			if _, dup := labels[label]; dup {
				return fmt.Errorf("prompt_template: named_templates[%q] label %q points to more than one version", nt.Name, label)
			}
			labels[label] = struct{}{}
		}
		if strings.TrimSpace(v.Content) == "" {
			return fmt.Errorf("prompt_template: named_templates[%q].versions[%d].content must not be blank", nt.Name, j)
		}
		if err := validatePlaceholders(v.Content); err != nil {
			return fmt.Errorf("prompt_template: named_templates[%q].versions[%d].content: %w", nt.Name, j, err)
		}
		if err := validateVersionContent(v.Content); err != nil {
			return fmt.Errorf("prompt_template: named_templates[%q].versions[%d].content: %w", nt.Name, j, err)
		}
		if err := validateRequiredVars(nt, v, j); err != nil {
			return err
		}
	}
	return nil
}

func validateRequiredVars(nt namedTemplate, v templateVersion, idx int) error {
	for name, rv := range v.RequiredVariables {
		switch rv.Type {
		case "string", "number", "boolean":
		default:
			return fmt.Errorf("prompt_template: named_templates[%q].versions[%d].required_variables[%q].type %q must be string, number, or boolean", nt.Name, idx, name, rv.Type)
		}
		if rv.MaxLength < 0 {
			return fmt.Errorf("prompt_template: named_templates[%q].versions[%d].required_variables[%q].max_length must be >= 0", nt.Name, idx, name)
		}
		for _, e := range rv.Enum {
			if strings.TrimSpace(e) == "" {
				return fmt.Errorf("prompt_template: named_templates[%q].versions[%d].required_variables[%q] has a blank enum entry", nt.Name, idx, name)
			}
		}
	}
	return nil
}

func validateVersionContent(content string) error {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "[") {
		return nil
	}
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(content), &elements); err != nil {
		return fmt.Errorf("must be a valid JSON messages array or a bare string template: %w", err)
	}
	for _, element := range elements {
		if !strings.HasPrefix(strings.TrimSpace(string(element)), "{") {
			return fmt.Errorf("must be a JSON array of message objects")
		}
	}
	return nil
}

func validatePlaceholders(content string) error {
	for _, m := range placeholderScanRe.FindAllStringSubmatch(content, -1) {
		name := strings.TrimSpace(m[1])
		if !placeholderNameRe.MatchString(name) {
			return fmt.Errorf("placeholder %q is not a valid [\\w.-]+ token", m[0])
		}
	}
	return nil
}
