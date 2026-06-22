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

package pertoolratelimit

import (
	"fmt"
	"path"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/pluginutil"
)

const (
	behaviorReject = "reject_response"
	behaviorInject = "inject_error_result"
	behaviorStrip  = "strip_tool_from_request"
)

var validScopes = map[string]struct{}{
	"consumer": {},
	"global":   {},
}

var enforceableBehaviors = map[string]struct{}{
	behaviorReject: {},
	behaviorInject: {},
	behaviorStrip:  {},
}

type windowConfig struct {
	Duration string `mapstructure:"duration"`
	Max      int    `mapstructure:"max"`
	seconds  int
}

type ruleConfig struct {
	Tool     string         `mapstructure:"tool"`
	Windows  []windowConfig `mapstructure:"windows"`
	Behavior string         `mapstructure:"behavior"`
}

type config struct {
	Scope           string       `mapstructure:"scope"`
	Rules           []ruleConfig `mapstructure:"rules"`
	BehaviorDefault string       `mapstructure:"behavior_default"`
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	for i := range cfg.Rules {
		for j := range cfg.Rules[i].Windows {
			cfg.Rules[i].Windows[j].seconds = cfg.Rules[i].Windows[j].windowSeconds()
		}
	}
	return &cfg, nil
}

func (c *config) validate() error {
	if c.Scope != "" {
		if _, ok := validScopes[c.Scope]; !ok {
			return fmt.Errorf("per_tool_rate_limiter: scope must be one of consumer, global")
		}
	}
	if err := validateBehavior(c.BehaviorDefault); err != nil {
		return fmt.Errorf("per_tool_rate_limiter: behavior_default: %w", err)
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("per_tool_rate_limiter: rules must not be empty")
	}
	for i := range c.Rules {
		rule := c.Rules[i]
		if err := rule.validate(); err != nil {
			return err
		}
		effective := rule.Behavior
		if effective == "" {
			effective = c.behaviorDefault()
		}
		if _, ok := enforceableBehaviors[effective]; !ok {
			return fmt.Errorf("per_tool_rate_limiter: rule %q: behavior %q is not supported", rule.Tool, effective)
		}
	}
	return nil
}

func (r ruleConfig) validate() error {
	if r.Tool == "" {
		return fmt.Errorf("per_tool_rate_limiter: rule tool must not be empty")
	}
	if _, err := path.Match(r.Tool, ""); err != nil {
		return fmt.Errorf("per_tool_rate_limiter: rule %q: invalid tool pattern: %w", r.Tool, err)
	}
	if len(r.Windows) == 0 {
		return fmt.Errorf("per_tool_rate_limiter: rule %q: at least one window is required", r.Tool)
	}
	for i := range r.Windows {
		w := r.Windows[i]
		d, err := time.ParseDuration(w.Duration)
		if err != nil {
			return fmt.Errorf("per_tool_rate_limiter: rule %q window %d: invalid duration %q: %w", r.Tool, i, w.Duration, err)
		}
		if secs := w.windowSeconds(); secs < 1 || time.Duration(secs)*time.Second != d {
			return fmt.Errorf("per_tool_rate_limiter: rule %q window %d: duration must be a whole number of seconds >= 1s", r.Tool, i)
		}
		if w.Max <= 0 {
			return fmt.Errorf("per_tool_rate_limiter: rule %q window %d: max must be > 0", r.Tool, i)
		}
	}
	return validateBehavior(r.Behavior)
}

func validateBehavior(behavior string) error {
	switch behavior {
	case "", behaviorReject, behaviorInject, behaviorStrip:
		return nil
	default:
		return fmt.Errorf("behavior must be one of reject_response, inject_error_result, strip_tool_from_request")
	}
}

func (c *config) behaviorDefault() string {
	if c.BehaviorDefault != "" {
		return c.BehaviorDefault
	}
	return behaviorReject
}

func (w windowConfig) windowSeconds() int {
	if w.seconds > 0 {
		return w.seconds
	}
	d, err := time.ParseDuration(w.Duration)
	if err != nil {
		return 0
	}
	return int(d.Seconds())
}
