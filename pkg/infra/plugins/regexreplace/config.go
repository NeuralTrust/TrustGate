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
	"time"

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

// Streaming defaults. The rules run locally, but they run over the whole
// prefix on every block — a pattern can straddle a block boundary, so the
// delta alone is not safe to match against — which makes the work quadratic in
// the length of the response. The cadence is what bounds it, so blocks are
// deliberately larger here than the cost of one pass would suggest.
var streamingDefaults = pluginutil.StreamingDefaults{
	HeadChars:            400,
	MinCharsBetweenEvals: 2048,
	MaxHoldMS:            500,
	MaxAccumulatedBytes:  262144,
	GuardTimeout:         time.Second,
}

type Settings struct {
	Target string `mapstructure:"target"`
	Rules  []Rule `mapstructure:"rules"`
	// Streaming opts the pre_response leg into per-block rewriting. Absent, a
	// streamed response is not rewritten at all, which is what this plugin did
	// before the block loop existed.
	Streaming pluginutil.StreamingSettings `mapstructure:"streaming"`

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
	// The buffered leg cannot fail: the rules are local and a rewrite that does
	// not apply leaves the text alone. The stream leg inherits fail_closed all
	// the same, because there its one failure mode is a rewrite that cannot
	// reach text already released, and releasing unmasked text is what the
	// rules exist to prevent.
	cfg.Streaming.ApplyDefaults(streamingDefaults, pluginutil.StreamOnErrorFailClosed)
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
	return s.Streaming.Validate(PluginName)
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
