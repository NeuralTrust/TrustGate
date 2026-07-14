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

package regexreplace

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const PluginName = "regex_replace"

const (
	targetRequest  = "request"
	targetResponse = "response"
)

var (
	ErrNoRules       = errors.New("regex_replace: at least one rule is required")
	ErrInvalidTarget = errors.New("regex_replace: target must be one of request, response")
	ErrEmptyPattern  = errors.New("regex_replace: rule pattern must not be empty")
	ErrBadPattern    = errors.New("regex_replace: invalid regular expression")
)

type Rule struct {
	Pattern         string `mapstructure:"pattern"`
	Replacement     string `mapstructure:"replacement"`
	CaseInsensitive bool   `mapstructure:"case_insensitive"`
	Multiline       bool   `mapstructure:"multiline"`
}

type Settings struct {
	Target string `mapstructure:"target"`
	Rules  []Rule `mapstructure:"rules"`

	compiled []compiledRule
}

type compiledRule struct {
	re          *regexp.Regexp
	replacement string
}

func parseConfig(settings map[string]any) (Settings, error) {
	cfg, err := pluginutil.Parse[Settings](settings)
	if err != nil {
		return Settings{}, err
	}
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	if err := cfg.compile(); err != nil {
		return Settings{}, err
	}
	return cfg, nil
}

func (s *Settings) validate() error {
	switch s.Target {
	case targetRequest, targetResponse:
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidTarget, s.Target)
	}
	if len(s.Rules) == 0 {
		return ErrNoRules
	}
	for i, r := range s.Rules {
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("%w: rule %d", ErrEmptyPattern, i)
		}
	}
	return nil
}

func (s *Settings) compile() error {
	compiled := make([]compiledRule, 0, len(s.Rules))
	for i, r := range s.Rules {
		re, err := regexp.Compile(buildPattern(r))
		if err != nil {
			return fmt.Errorf("%w: rule %d: %w", ErrBadPattern, i, err)
		}
		compiled = append(compiled, compiledRule{re: re, replacement: r.Replacement})
	}
	s.compiled = compiled
	return nil
}

func buildPattern(r Rule) string {
	var b strings.Builder
	if r.CaseInsensitive {
		b.WriteString("(?i)")
	}
	if r.Multiline {
		b.WriteString("(?m)")
	}
	b.WriteString(r.Pattern)
	return b.String()
}

func (s Settings) isRequestLeg() bool {
	return s.Target == targetRequest
}

func (s Settings) isResponseLeg() bool {
	return s.Target == targetResponse
}
