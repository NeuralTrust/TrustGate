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

package tokenratelimit

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	unitTokens  = "tokens"
	unitDollars = "dollars"

	countingTotal  = "total"
	countingInput  = "input"
	countingOutput = "output"

	pricingBuiltin = "builtin"
	pricingCustom  = "custom"

	behaviorReject         = "reject"
	behaviorThrottle       = "throttle"
	behaviorDowngradeModel = "downgrade_model"
	behaviorDowngrade      = "downgrade"
	behaviorAlertOnly      = "alert_only"

	unknownReject      = "reject"
	unknownPassThrough = "pass_through"
	unknownAssumeMax   = "assume_max"

	minWindowSeconds = 60
)

type windowConfig struct {
	Unit string `mapstructure:"unit"`
	Max  int    `mapstructure:"max"`
}

type budgetRule struct {
	Model      string  `mapstructure:"model"`
	Max        float64 `mapstructure:"max"`
	TimeWindow string  `mapstructure:"time_window"`
}

type aggregateConfig struct {
	Max        float64 `mapstructure:"max"`
	TimeWindow string  `mapstructure:"time_window"`
}

type costCeiling struct {
	MaxInputCostPer1k  float64 `mapstructure:"max_input_cost_per_1k_tokens"`
	MaxOutputCostPer1k float64 `mapstructure:"max_output_cost_per_1k_tokens"`
}

type costCapConfig struct {
	Enabled             bool                   `mapstructure:"enabled"`
	MaxInputCostPer1k   float64                `mapstructure:"max_input_cost_per_1k_tokens"`
	MaxOutputCostPer1k  float64                `mapstructure:"max_output_cost_per_1k_tokens"`
	PerModelOverrides   map[string]costCeiling `mapstructure:"per_model_overrides"`
	BehaviorOnViolation string                 `mapstructure:"behavior_on_violation"`
	DowngradeTo         string                 `mapstructure:"downgrade_to"`
	UnknownModel        string                 `mapstructure:"unknown_model"`
}

type customPrice struct {
	Input  float64 `mapstructure:"input"`
	Output float64 `mapstructure:"output"`
}

type config struct {
	Unit                 string                 `mapstructure:"unit"`
	PerModel             bool                   `mapstructure:"per_model"`
	Counting             string                 `mapstructure:"counting"`
	Rules                []budgetRule           `mapstructure:"rules"`
	Aggregate            *aggregateConfig       `mapstructure:"aggregate"`
	BehaviorOnExceeded   string                 `mapstructure:"behavior_on_exceeded"`
	DowngradeTo          string                 `mapstructure:"downgrade_to"`
	StreamUsageInjection bool                   `mapstructure:"stream_usage_injection"`
	CountCacheReads      bool                   `mapstructure:"count_cache_reads"`
	CostCap              *costCapConfig         `mapstructure:"cost_cap"`
	PricingTable         string                 `mapstructure:"pricing_table"`
	CustomPricing        map[string]customPrice `mapstructure:"custom_pricing"`
	Window               windowConfig           `mapstructure:"window"`
	GroupByHeader        string                 `mapstructure:"group_by_header"`
}

var validUnits = map[string]int{
	"second": 1,
	"minute": 60,
	"hour":   3600,
	"day":    86400,
}

func parseConfig(settings map[string]any) (*config, error) {
	cfg, err := pluginutil.Parse[config](settings)
	if err != nil {
		return nil, err
	}
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *config) normalize() {
	if c.Unit == "" {
		c.Unit = unitTokens
	}
	if c.Counting == "" {
		c.Counting = countingTotal
	}
	if c.PricingTable == "" {
		c.PricingTable = pricingBuiltin
	}
	if c.BehaviorOnExceeded == "" {
		c.BehaviorOnExceeded = behaviorReject
	}
	if len(c.Rules) == 0 && c.Aggregate == nil && c.Window.Max > 0 {
		c.Aggregate = &aggregateConfig{Max: float64(c.Window.Max)}
	}
}

func (c *config) validate() error {
	switch c.Unit {
	case unitTokens, unitDollars:
	default:
		return fmt.Errorf("token_rate_limiter: unit must be one of tokens, dollars")
	}

	switch c.Counting {
	case countingTotal, countingInput, countingOutput:
	default:
		return fmt.Errorf("token_rate_limiter: counting must be one of total, input, output")
	}

	switch c.PricingTable {
	case pricingBuiltin, pricingCustom:
	default:
		return fmt.Errorf("token_rate_limiter: pricing_table must be one of builtin, custom")
	}

	if c.Unit == unitDollars && c.PricingTable == pricingCustom && len(c.CustomPricing) == 0 {
		return fmt.Errorf("token_rate_limiter: pricing_table=custom requires non-empty custom_pricing")
	}

	switch c.BehaviorOnExceeded {
	case behaviorReject, behaviorThrottle, behaviorDowngradeModel, behaviorAlertOnly:
	default:
		return fmt.Errorf("token_rate_limiter: behavior_on_exceeded must be one of reject, throttle, downgrade_model, alert_only")
	}
	if strings.HasPrefix(c.BehaviorOnExceeded, behaviorDowngrade) && c.DowngradeTo == "" {
		return fmt.Errorf("token_rate_limiter: behavior_on_exceeded=%s requires downgrade_to", c.BehaviorOnExceeded)
	}

	hasLegacyWindow := c.Window.Max > 0
	if hasLegacyWindow {
		if _, ok := validUnits[strings.ToLower(c.Window.Unit)]; !ok {
			return fmt.Errorf("token_rate_limiter: window.unit must be one of second, minute, hour, day")
		}
	}

	if c.PerModel && len(c.Rules) == 0 && !hasLegacyWindow {
		return fmt.Errorf("token_rate_limiter: per_model requires rules or a legacy window")
	}

	for i := range c.Rules {
		if c.Rules[i].Max <= 0 {
			return fmt.Errorf("token_rate_limiter: rules[%d].max must be > 0", i)
		}
		if c.Unit == unitTokens && !isWholeNumber(c.Rules[i].Max) {
			return fmt.Errorf("token_rate_limiter: rules[%d].max must be a whole number of tokens", i)
		}
		if c.Rules[i].TimeWindow != "" {
			if _, err := parseWindow(c.Rules[i].TimeWindow); err != nil {
				return fmt.Errorf("token_rate_limiter: rules[%d].time_window: %w", i, err)
			}
		}
	}

	if c.Aggregate != nil {
		if c.Aggregate.Max <= 0 {
			return fmt.Errorf("token_rate_limiter: aggregate.max must be > 0")
		}
		if c.Unit == unitTokens && !isWholeNumber(c.Aggregate.Max) {
			return fmt.Errorf("token_rate_limiter: aggregate.max must be a whole number of tokens")
		}
		if c.Aggregate.TimeWindow != "" {
			if _, err := parseWindow(c.Aggregate.TimeWindow); err != nil {
				return fmt.Errorf("token_rate_limiter: aggregate.time_window: %w", err)
			}
		}
	}

	if c.CostCap != nil {
		if err := c.CostCap.validate(); err != nil {
			return err
		}
	}

	if !hasLegacyWindow && len(c.Rules) == 0 && c.Aggregate == nil && (c.CostCap == nil || !c.CostCap.Enabled) {
		return fmt.Errorf("token_rate_limiter: at least one of window, rules, aggregate, or cost_cap must be set")
	}

	return nil
}

func (c *costCapConfig) validate() error {
	if !c.Enabled {
		return nil
	}

	switch c.UnknownModel {
	case "", unknownReject, unknownPassThrough, unknownAssumeMax:
	default:
		return fmt.Errorf("token_rate_limiter: cost_cap.unknown_model must be one of reject, pass_through, assume_max")
	}

	switch c.BehaviorOnViolation {
	case "", behaviorReject, behaviorDowngrade:
	default:
		return fmt.Errorf("token_rate_limiter: cost_cap.behavior_on_violation must be one of reject, downgrade")
	}
	if strings.HasPrefix(c.BehaviorOnViolation, behaviorDowngrade) && c.DowngradeTo == "" {
		return fmt.Errorf("token_rate_limiter: cost_cap.behavior_on_violation=%s requires downgrade_to", c.BehaviorOnViolation)
	}

	if c.MaxInputCostPer1k < 0 || c.MaxOutputCostPer1k < 0 {
		return fmt.Errorf("token_rate_limiter: cost_cap ceilings must be >= 0")
	}
	for k := range c.PerModelOverrides {
		if c.PerModelOverrides[k].MaxInputCostPer1k < 0 || c.PerModelOverrides[k].MaxOutputCostPer1k < 0 {
			return fmt.Errorf("token_rate_limiter: cost_cap.per_model_overrides[%q] ceilings must be >= 0", k)
		}
	}
	return nil
}

func parseWindow(s string) (int, error) {
	trimmed := strings.TrimSpace(strings.ToLower(s))
	if len(trimmed) < 2 {
		return 0, fmt.Errorf("invalid time_window %q", s)
	}

	unit := trimmed[len(trimmed)-1]
	n, err := strconv.Atoi(trimmed[:len(trimmed)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid time_window %q: %w", s, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid time_window %q: must be positive", s)
	}

	var secs int
	switch unit {
	case 's':
		secs = n
	case 'm':
		secs = n * 60
	case 'h':
		secs = n * 3600
	case 'd':
		secs = n * 86400
	default:
		return 0, fmt.Errorf("invalid time_window %q: unit must be one of s, m, h, d", s)
	}

	if secs < minWindowSeconds {
		secs = minWindowSeconds
	}
	return secs, nil
}

func (c *config) windowSeconds() int {
	if secs, ok := validUnits[strings.ToLower(c.Window.Unit)]; ok {
		return secs
	}
	return validUnits["minute"]
}

func isWholeNumber(f float64) bool {
	return f == math.Trunc(f)
}
