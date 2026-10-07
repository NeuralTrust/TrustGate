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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigNormalizeDefaults(t *testing.T) {
	c := &config{Window: windowConfig{Unit: "minute", Max: 100}}
	c.normalize()

	assert.Equal(t, unitTokens, c.Unit)
	assert.Equal(t, countingTotal, c.Counting)
	assert.Equal(t, behaviorReject, c.BehaviorOnExceeded)
}

func TestConfigNormalizePreservesExplicitValues(t *testing.T) {
	c := &config{
		Unit:               unitDollars,
		Counting:           countingInput,
		BehaviorOnExceeded: behaviorDowngradeModel,
		Aggregate:          &aggregateConfig{Max: 5, TimeWindow: "1h"},
	}
	c.normalize()

	assert.Equal(t, unitDollars, c.Unit)
	assert.Equal(t, countingInput, c.Counting)
	assert.Equal(t, behaviorDowngradeModel, c.BehaviorOnExceeded)
}

func TestConfigNormalizeSynthesizesAggregateFromLegacyWindow(t *testing.T) {
	c := &config{Window: windowConfig{Unit: "hour", Max: 1000}, GroupByHeader: "X-User"}
	c.normalize()

	require.NotNil(t, c.Aggregate)
	assert.Equal(t, float64(1000), c.Aggregate.Max)
	assert.Equal(t, "", c.Aggregate.TimeWindow)
	assert.Equal(t, 3600, c.windowSeconds())
}

func TestConfigNormalizeDoesNotOverrideExistingAggregate(t *testing.T) {
	c := &config{
		Window:    windowConfig{Unit: "hour", Max: 1000},
		Aggregate: &aggregateConfig{Max: 50, TimeWindow: "30m"},
	}
	c.normalize()

	assert.Equal(t, float64(50), c.Aggregate.Max)
	assert.Equal(t, "30m", c.Aggregate.TimeWindow)
}

func TestConfigNormalizeLegacyWindowCapsAlongsideRules(t *testing.T) {
	c := &config{
		PerModel: true,
		Window:   windowConfig{Unit: "hour", Max: 1000},
		Rules:    []budgetRule{{Model: "gpt-5", Max: 100, TimeWindow: "1h"}},
	}
	c.normalize()

	require.NotNil(t, c.Aggregate, "a legacy window must stay a catch-all aggregate so non-rule models are not left uncapped")
	assert.Equal(t, float64(1000), c.Aggregate.Max)
}

func TestConfigNormalizeRulesWithoutLegacyWindowHaveNoAggregate(t *testing.T) {
	c := &config{
		PerModel: true,
		Rules:    []budgetRule{{Model: "gpt-5", Max: 100, TimeWindow: "1h"}},
	}
	c.normalize()

	assert.Nil(t, c.Aggregate)
}

func TestConfigNormalizeRulesImplyPerModel(t *testing.T) {
	c := &config{Rules: []budgetRule{{Model: "gpt-5", Max: 100, TimeWindow: "1h"}}}
	c.normalize()

	assert.True(t, c.PerModel, "rules must enforce per-model keying so they are not silently ignored")
}

func validConfig(mutate func(*config)) *config {
	c := &config{
		Unit:               unitTokens,
		Counting:           countingTotal,
		BehaviorOnExceeded: behaviorReject,
		Aggregate:          &aggregateConfig{Max: 1000, TimeWindow: "1h"},
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config
		wantErr bool
	}{
		{
			name: "valid aggregate token budget",
			cfg:  validConfig(nil),
		},
		{
			name: "valid legacy window after normalize",
			cfg: func() *config {
				c := &config{Window: windowConfig{Unit: "hour", Max: 1000}}
				c.normalize()
				return c
			}(),
		},
		{
			name: "valid per-model rules",
			cfg: validConfig(func(c *config) {
				c.PerModel = true
				c.Aggregate = nil
				c.Rules = []budgetRule{{Model: "gpt-5", Max: 1000, TimeWindow: "1h"}}
			}),
		},
		{
			name: "valid dollars with custom pricing",
			cfg: validConfig(func(c *config) {
				c.Unit = unitDollars
				c.CustomPricing = map[string]llmcost.CustomPrice{"gpt-5": {Input: 0.00001, Output: 0.00003}}
			}),
		},
		{
			name: "valid downgrade with target",
			cfg: validConfig(func(c *config) {
				c.BehaviorOnExceeded = behaviorDowngradeModel
				c.DowngradeTo = "gpt-5-mini"
			}),
		},
		{
			name: "valid cost cap only",
			cfg: validConfig(func(c *config) {
				c.Aggregate = nil
				c.CostCap = &llmcost.CapConfig{Enabled: true, MaxInputCostPer1k: 0.5, MaxOutputCostPer1k: 1.5, UnknownModel: llmcost.UnknownReject, BehaviorOnViolation: llmcost.BehaviorReject}
			}),
		},
		{
			name:    "invalid unit",
			cfg:     validConfig(func(c *config) { c.Unit = "credits" }),
			wantErr: true,
		},
		{
			name:    "invalid counting",
			cfg:     validConfig(func(c *config) { c.Counting = "prompt" }),
			wantErr: true,
		},
		{
			name: "per_model without rules or window",
			cfg: validConfig(func(c *config) {
				c.PerModel = true
				c.Aggregate = nil
			}),
			wantErr: true,
		},
		{
			name: "downgrade without target",
			cfg: validConfig(func(c *config) {
				c.BehaviorOnExceeded = behaviorDowngradeModel
			}),
			wantErr: true,
		},
		{
			name: "rule max non-positive",
			cfg: validConfig(func(c *config) {
				c.Aggregate = nil
				c.Rules = []budgetRule{{Model: "gpt-5", Max: 0, TimeWindow: "1h"}}
			}),
			wantErr: true,
		},
		{
			name: "rule malformed time window",
			cfg: validConfig(func(c *config) {
				c.Aggregate = nil
				c.Rules = []budgetRule{{Model: "gpt-5", Max: 100, TimeWindow: "1y"}}
			}),
			wantErr: true,
		},
		{
			name: "aggregate max non-positive",
			cfg: validConfig(func(c *config) {
				c.Aggregate = &aggregateConfig{Max: 0, TimeWindow: "1h"}
			}),
			wantErr: true,
		},
		{
			name: "aggregate malformed time window",
			cfg: validConfig(func(c *config) {
				c.Aggregate = &aggregateConfig{Max: 100, TimeWindow: "bogus"}
			}),
			wantErr: true,
		},
		{
			name: "cost cap bad unknown model",
			cfg: validConfig(func(c *config) {
				c.CostCap = &llmcost.CapConfig{Enabled: true, UnknownModel: "maybe"}
			}),
			wantErr: true,
		},
		{
			name: "cost cap bad behavior on violation",
			cfg: validConfig(func(c *config) {
				c.CostCap = &llmcost.CapConfig{Enabled: true, BehaviorOnViolation: "explode"}
			}),
			wantErr: true,
		},
		{
			name: "cost cap downgrade without target",
			cfg: validConfig(func(c *config) {
				c.CostCap = &llmcost.CapConfig{Enabled: true, BehaviorOnViolation: llmcost.BehaviorDowngrade}
			}),
			wantErr: true,
		},
		{
			name: "cost cap negative ceiling",
			cfg: validConfig(func(c *config) {
				c.CostCap = &llmcost.CapConfig{Enabled: true, MaxInputCostPer1k: -1}
			}),
			wantErr: true,
		},
		{
			name: "cost cap negative override ceiling",
			cfg: validConfig(func(c *config) {
				c.CostCap = &llmcost.CapConfig{Enabled: true, PerModelOverrides: map[string]llmcost.Ceiling{"gpt-5": {MaxOutputCostPer1k: -2}}}
			}),
			wantErr: true,
		},
		{
			name: "rule without time window and no legacy window",
			cfg: validConfig(func(c *config) {
				c.PerModel = true
				c.Aggregate = nil
				c.Rules = []budgetRule{{Model: "gpt-5", Max: 100}}
			}),
			wantErr: true,
		},
		{
			name: "rule without time window inherits legacy window",
			cfg: validConfig(func(c *config) {
				c.PerModel = true
				c.Aggregate = nil
				c.Window = windowConfig{Unit: "hour", Max: 1000}
				c.Rules = []budgetRule{{Model: "gpt-5", Max: 100}}
			}),
		},
		{
			name: "aggregate without time window and no legacy window",
			cfg: validConfig(func(c *config) {
				c.Aggregate = &aggregateConfig{Max: 1000}
			}),
			wantErr: true,
		},
		{
			name: "dollars cannot use legacy window",
			cfg: validConfig(func(c *config) {
				c.Unit = unitDollars
				c.CustomPricing = map[string]llmcost.CustomPrice{"gpt-5": {Input: 0.00001, Output: 0.00003}}
				c.Window = windowConfig{Unit: "hour", Max: 1000}
			}),
			wantErr: true,
		},
		{
			name:    "nothing configured",
			cfg:     validConfig(func(c *config) { c.Aggregate = nil }),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestParseConfigBackCompat(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"window":          map[string]any{"unit": "hour", "max": 1000},
		"group_by_header": "X-User",
	})
	require.NoError(t, err)
	assert.Equal(t, unitTokens, cfg.Unit)
	assert.Equal(t, behaviorReject, cfg.BehaviorOnExceeded)
	assert.Equal(t, "X-User", cfg.GroupByHeader)
	require.NotNil(t, cfg.Aggregate)
	assert.Equal(t, float64(1000), cfg.Aggregate.Max)
	assert.Equal(t, 3600, cfg.windowSeconds())
}

func TestParseConfigRejectsInvalid(t *testing.T) {
	_, err := parseConfig(map[string]any{"unit": "credits"})
	require.Error(t, err)
}

func TestParseWindow(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{name: "minutes", in: "30m", want: 1800},
		{name: "hour", in: "1h", want: 3600},
		{name: "day", in: "1d", want: 86400},
		{name: "ninety minutes", in: "90m", want: 5400},
		{name: "seconds floored", in: "30s", want: 60},
		{name: "minute floor exact", in: "1m", want: 60},
		{name: "uppercase", in: "2H", want: 7200},
		{name: "empty", in: "", wantErr: true},
		{name: "no unit", in: "30", wantErr: true},
		{name: "bad unit", in: "1y", wantErr: true},
		{name: "non numeric", in: "abch", wantErr: true},
		{name: "zero", in: "0h", wantErr: true},
		{name: "negative", in: "-1h", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWindow(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfigValidate_Partition(t *testing.T) {
	key := func(mutate func(*config)) *config {
		return validConfig(func(c *config) { c.Partition = partitionKey; mutate(c) })
	}
	priced := map[string]llmcost.CustomPrice{"gpt-5": {Input: 1, Output: 2}}
	dailyRule := []budgetRule{{Model: "gpt-5", Max: 10, TimeWindow: windowCalendarDay}}
	tests := []struct {
		name    string
		cfg     *config
		wantErr string
	}{
		{name: "no partition keeps group by header and custom pricing", cfg: validConfig(func(c *config) { c.GroupByHeader, c.CustomPricing = "X-Team", priced })},
		{name: "unknown partition", cfg: validConfig(func(c *config) { c.Partition = "owner" }), wantErr: "partition must be key"},
		{name: "calendar month without partition", cfg: validConfig(func(c *config) { c.Aggregate.TimeWindow = windowCalendarMonth }), wantErr: "aggregate.time_window: calendar_month requires partition key"},
		{name: "calendar day rule without partition", cfg: validConfig(func(c *config) { c.Rules = dailyRule }), wantErr: "rules[0].time_window: calendar_day requires partition key"},
		{name: "key with a rolling window", cfg: key(func(c *config) { c.Aggregate.TimeWindow = "24h" })},
		{name: "key with calendar windows", cfg: key(func(c *config) { c.Aggregate.TimeWindow, c.Rules = windowCalendarMonth, dailyRule })},
		{name: "key with custom pricing", cfg: key(func(c *config) { c.CustomPricing = priced }), wantErr: "does not support custom_pricing"},
		{name: "key with group by header", cfg: key(func(c *config) { c.GroupByHeader = "X-Team" }), wantErr: "does not support group_by_header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestCalendarPeriod(t *testing.T) {
	at := func(month time.Month, day, hour, minute, sec int) time.Time {
		return time.Date(2026, month, day, hour, minute, sec, 0, time.UTC)
	}
	tests := []struct {
		name       string
		window     string
		at, now    time.Time
		wantPeriod string
		wantTTL    int
	}{
		{name: "december ends at the new year", window: windowCalendarMonth, now: at(12, 31, 0, 0, 0), wantPeriod: "2026-12", wantTTL: 86400},
		{name: "ttl floor", window: windowCalendarMonth, now: at(10, 31, 23, 59, 30), wantPeriod: "2026-10", wantTTL: minWindowSeconds},
		{name: "day", window: windowCalendarDay, now: at(10, 2, 18, 0, 0), wantPeriod: "2026-10-02", wantTTL: 6 * 3600},
		{name: "day in UTC", window: windowCalendarDay, now: at(10, 2, 23, 0, 0).In(time.FixedZone("CEST", 7200)), wantPeriod: "2026-10-02", wantTTL: 3600},
		{name: "rolling window", window: "24h", now: at(10, 2, 18, 0, 0)},
		{name: "a request admitted in october is charged to october", window: windowCalendarMonth,
			at: at(10, 31, 23, 59, 58), now: at(11, 1, 0, 0, 5), wantPeriod: "2026-10", wantTTL: minWindowSeconds},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arrived := tt.at
			if arrived.IsZero() {
				arrived = tt.now
			}
			period, ttl, ok := calendarPeriod(tt.window, arrived, tt.now)
			assert.Equal(t, tt.wantPeriod != "", ok)
			assert.Equal(t, tt.wantPeriod, period)
			assert.Equal(t, tt.wantTTL, ttl)
		})
	}
}

func TestConfigNormalizeCanonicalizesOnlyCalendarWindows(t *testing.T) {
	c := &config{
		Partition: partitionKey,
		Rules:     []budgetRule{{Model: "gpt-5", Max: 10, TimeWindow: " Calendar_Day "}, {Model: "gpt-4", Max: 10, TimeWindow: " 24H "}},
		Aggregate: &aggregateConfig{Max: 100, TimeWindow: "CALENDAR_MONTH"},
	}
	c.normalize()

	assert.Equal(t, windowCalendarDay, c.Rules[0].TimeWindow)
	assert.Equal(t, " 24H ", c.Rules[1].TimeWindow, "rolling windows keep their spelling")
	assert.Equal(t, windowCalendarMonth, c.Aggregate.TimeWindow)
	require.NoError(t, c.validate())
}
