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

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
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
//
// Unlike the guardrails it sits beside, it is on by default: the rewrite is
// local, costs no provider call, and a masking policy that lets the same text
// through the moment a client streams is not masking. A policy opts out with
// streaming.enabled: false.
var streamingDefaults = pluginutil.StreamingDefaults{
	EnabledByDefault:     true,
	HeadChars:            400,
	MinCharsBetweenEvals: 2048,
	MaxHoldMS:            500,
	MaxAccumulatedBytes:  262144,
	GuardTimeout:         time.Second,
}

type Settings struct {
	Target string `mapstructure:"target"`
	Rules  []Rule `mapstructure:"rules"`
	// Streaming configures per-block rewriting of the pre_response leg. Absent,
	// it is on; only an explicit enabled: false leaves a streamed response
	// unrewritten.
	Streaming streamingSettings `mapstructure:"streaming"`

	compiled []compiledRule
}

// streamingSettings is the shared streaming block plus the one key regex_replace
// keeps beside it. The rewrite is a mask, not a guardrail: when a block cannot
// be rewritten the held text is unmasked, so the stream leg fails closed unless
// the policy says otherwise.
type streamingSettings struct {
	pluginutil.StreamingSettings `mapstructure:",squash"`
	OnError                      string `mapstructure:"on_error"`
}

func (s *streamingSettings) applyDefaults() {
	s.ApplyDefaults(streamingDefaults)
	if s.OnError == "" {
		s.OnError = pluginutil.StreamOnErrorFailClosed
	}
}

func (s streamingSettings) validate() error {
	switch s.OnError {
	case pluginutil.StreamOnErrorFailOpen, pluginutil.StreamOnErrorFailClosed:
	default:
		return fmt.Errorf("%s: streaming.on_error must be one of fail_open, fail_closed", PluginName)
	}
	return s.Validate(PluginName)
}

func (s streamingSettings) Options() appplugins.StreamOptions {
	opts := s.StreamingSettings.Options()
	opts.OnError = s.OnError
	return opts
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
	// not apply leaves the text alone. The stream leg defaults to fail_closed all
	// the same, because there its one failure mode is a rewrite that cannot
	// reach text already released, and releasing unmasked text is what the
	// rules exist to prevent.
	cfg.Streaming.applyDefaults()
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
	return s.Streaming.validate()
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

// RetiredSettings lists the settings keys this policy never stores: the plugin
// ignores them, so a stored value would read as behaviour the policy does not
// have.
// streaming.on_error is not among them: regex_replace is a rewriter and its
// stream leg fails closed on it.
func (p *Plugin) RetiredSettings() []string {
	return []string{
		pluginutil.SettingOnMaskFailure,
	}
}
