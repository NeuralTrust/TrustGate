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
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	unitTokens  = authdomain.BudgetUnitTokens
	unitDollars = authdomain.BudgetUnitDollars

	countingTotal  = "total"
	countingInput  = "input"
	countingOutput = "output"

	behaviorReject         = "reject"
	behaviorDowngradeModel = "downgrade_model"
	behaviorDowngrade      = "downgrade"

	minWindowSeconds = 60

	partitionKey        = "key"
	windowCalendarMonth = authdomain.BudgetWindowCalendarMonth
	windowCalendarDay   = authdomain.BudgetWindowCalendarDay
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

type config struct {
	Unit               string                         `mapstructure:"unit"`
	PerModel           bool                           `mapstructure:"per_model"`
	Counting           string                         `mapstructure:"counting"`
	Rules              []budgetRule                   `mapstructure:"rules"`
	Aggregate          *aggregateConfig               `mapstructure:"aggregate"`
	BehaviorOnExceeded string                         `mapstructure:"behavior_on_exceeded"`
	DowngradeTo        string                         `mapstructure:"downgrade_to"`
	CountCacheReads    bool                           `mapstructure:"count_cache_reads"`
	CostCap            *llmcost.CapConfig             `mapstructure:"cost_cap"`
	CustomPricing      map[string]llmcost.CustomPrice `mapstructure:"custom_pricing"`
	Window             windowConfig                   `mapstructure:"window"`
	GroupByHeader      string                         `mapstructure:"group_by_header"`
	Partition          string                         `mapstructure:"partition"`
	// KeyBudgets makes the policy hold each key to the budget it carries, in
	// place of the aggregate. Only a policy that opts in reads key budgets, so
	// a tenant's own partition key policy keeps its limit and its unit.
	KeyBudgets bool `mapstructure:"key_budgets"`
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
	if c.BehaviorOnExceeded == "" {
		c.BehaviorOnExceeded = behaviorReject
	}
	if len(c.Rules) > 0 {
		c.PerModel = true
	}
	if c.Aggregate == nil && c.Window.Max > 0 {
		c.Aggregate = &aggregateConfig{Max: float64(c.Window.Max)}
	}
	for i := range c.Rules {
		c.Rules[i].TimeWindow = canonicalCalendarWindow(c.Rules[i].TimeWindow)
	}
	if c.Aggregate != nil {
		c.Aggregate.TimeWindow = canonicalCalendarWindow(c.Aggregate.TimeWindow)
	}
}

func canonicalCalendarWindow(window string) string {
	if canonical := strings.ToLower(strings.TrimSpace(window)); isCalendarWindow(canonical) {
		return canonical
	}
	return window
}

func (c *config) validate() error {
	if err := c.validatePartition(); err != nil {
		return err
	}

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

	switch c.BehaviorOnExceeded {
	case behaviorReject, behaviorDowngradeModel:
	default:
		return fmt.Errorf("token_rate_limiter: behavior_on_exceeded must be one of reject, downgrade_model")
	}
	if strings.HasPrefix(c.BehaviorOnExceeded, behaviorDowngrade) && c.DowngradeTo == "" {
		return fmt.Errorf("token_rate_limiter: behavior_on_exceeded=%s requires downgrade_to", c.BehaviorOnExceeded)
	}

	hasLegacyWindow := c.Window.Max > 0
	if hasLegacyWindow {
		if _, ok := validUnits[strings.ToLower(c.Window.Unit)]; !ok {
			return fmt.Errorf("token_rate_limiter: window.unit must be one of second, minute, hour, day")
		}
		if c.Unit == unitDollars {
			return fmt.Errorf("token_rate_limiter: dollar budgets cannot use the legacy window block; configure aggregate or rules with explicit dollar maxima")
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
		if c.Rules[i].TimeWindow == "" {
			if !hasLegacyWindow {
				return fmt.Errorf("token_rate_limiter: rules[%d].time_window is required when no legacy window is set", i)
			}
		} else if err := c.validateWindow(c.Rules[i].TimeWindow); err != nil {
			return fmt.Errorf("token_rate_limiter: rules[%d].time_window: %w", i, err)
		}
	}

	if c.Aggregate != nil {
		if c.Aggregate.Max <= 0 {
			return fmt.Errorf("token_rate_limiter: aggregate.max must be > 0")
		}
		if c.Unit == unitTokens && !isWholeNumber(c.Aggregate.Max) {
			return fmt.Errorf("token_rate_limiter: aggregate.max must be a whole number of tokens")
		}
		if c.Aggregate.TimeWindow == "" {
			if !hasLegacyWindow {
				return fmt.Errorf("token_rate_limiter: aggregate.time_window is required when no legacy window is set")
			}
		} else if err := c.validateWindow(c.Aggregate.TimeWindow); err != nil {
			return fmt.Errorf("token_rate_limiter: aggregate.time_window: %w", err)
		}
	}

	if c.CostCap != nil {
		if err := c.CostCap.Validate(); err != nil {
			return fmt.Errorf("token_rate_limiter: %w", err)
		}
	}

	if !c.KeyBudgets && !c.limits() {
		return fmt.Errorf("token_rate_limiter: at least one of window, rules, aggregate, or cost_cap must be set")
	}

	return nil
}

// limits reports whether the config sets a limit of its own. With key_budgets
// it may set none and cap only the keys that carry a budget.
func (c *config) limits() bool {
	return c.Window.Max > 0 || len(c.Rules) > 0 || c.Aggregate != nil || (c.CostCap != nil && c.CostCap.Enabled)
}

// forKey returns the config one request is held to under key_budgets: the
// budget of the request's key, when it has one in the policy's unit, replaces
// the aggregate. The parsed config is left as it is, so no other request ever
// sees the budget.
func (c *config) forKey(budget *authdomain.KeyBudget) *config {
	if !c.KeyBudgets || budget == nil || budget.Unit != c.Unit {
		return c
	}
	scoped := *c
	scoped.Aggregate = &aggregateConfig{Max: budget.Max, TimeWindow: budget.TimeWindow}
	return &scoped
}

func (c *config) validatePartition() error {
	switch {
	case c.Partition == "" && c.KeyBudgets:
		return fmt.Errorf("token_rate_limiter: key_budgets requires partition %s", partitionKey)
	case c.Partition == "":
		return nil
	case c.Partition != partitionKey:
		return fmt.Errorf("token_rate_limiter: partition must be %s when set", partitionKey)
	case len(c.CustomPricing) > 0:
		return fmt.Errorf("token_rate_limiter: partition %s does not support custom_pricing", partitionKey)
	case c.GroupByHeader != "":
		return fmt.Errorf("token_rate_limiter: partition %s does not support group_by_header", partitionKey)
	case c.BehaviorOnExceeded == behaviorDowngradeModel:
		return fmt.Errorf("token_rate_limiter: partition %s does not support behavior_on_exceeded=%s", partitionKey, behaviorDowngradeModel)
	}
	return nil
}

// keyPartitioned reports a policy that counts per key. Such a policy is a hard
// limit: it fails closed when the counter store is down and refuses a model it
// cannot price in a dollar budget.
func (c *config) keyPartitioned() bool {
	return c.Partition == partitionKey
}

func (c *config) refusesUnpriced() bool {
	return c.keyPartitioned() && c.Unit == unitDollars
}

func (c *config) validateWindow(window string) error {
	if !isCalendarWindow(window) {
		_, err := parseWindow(window)
		return err
	}
	if c.Partition != partitionKey {
		return fmt.Errorf("%s requires partition %s", window, partitionKey)
	}
	return nil
}

func isCalendarWindow(window string) bool {
	return window == windowCalendarMonth || window == windowCalendarDay
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

// calendarPeriod names the calendar period at falls in and how long its counter
// lives from now. Both stages of a request pass the time the request arrived as
// at, so a request that ends after the period does is still charged to the
// period that admitted it.
func calendarPeriod(window string, at, now time.Time) (period string, ttlSeconds int, ok bool) {
	at = at.UTC()
	var start, end time.Time
	var layout string
	switch window {
	case windowCalendarMonth:
		start = time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		end, layout = start.AddDate(0, 1, 0), "2006-01"
	case windowCalendarDay:
		start = time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		end, layout = start.AddDate(0, 0, 1), "2006-01-02"
	default:
		return "", 0, false
	}
	ttl := int(math.Ceil(end.Sub(now).Seconds()))
	return start.Format(layout), max(ttl, minWindowSeconds), true
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
