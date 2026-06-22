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

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectRule(t *testing.T) {
	rules := []budgetRule{
		{Model: "gpt-5", Max: 100, TimeWindow: "1h"},
		{Model: "claude-opus-*", Max: 200, TimeWindow: "1h"},
		{Model: "claude-opus-4", Max: 300, TimeWindow: "1h"},
	}
	cfg := &config{Rules: rules}

	tests := []struct {
		name      string
		model     string
		wantFound bool
		wantModel string
	}{
		{name: "exact match", model: "gpt-5", wantFound: true, wantModel: "gpt-5"},
		{name: "exact beats glob", model: "claude-opus-4", wantFound: true, wantModel: "claude-opus-4"},
		{name: "glob match", model: "claude-opus-4-1", wantFound: true, wantModel: "claude-opus-*"},
		{name: "no match", model: "gemini-2", wantFound: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := selectRule(cfg, tt.model)
			assert.Equal(t, tt.wantFound, ok)
			if tt.wantFound {
				assert.Equal(t, tt.wantModel, r.Model)
			}
		})
	}
}

func TestSelectRule_NoRules(t *testing.T) {
	_, ok := selectRule(&config{}, "gpt-5")
	assert.False(t, ok)
}

func TestWindowsFor(t *testing.T) {
	base := "trl:cfg-1:consumer:co-9"

	t.Run("aggregate only", func(t *testing.T) {
		cfg := &config{Aggregate: &aggregateConfig{Max: 1000, TimeWindow: "1h"}}
		windows := windowsFor(cfg, base, "gpt-5")
		require.Len(t, windows, 1)
		assert.Equal(t, base, windows[0].key)
		assert.Equal(t, float64(1000), windows[0].max)
		assert.Equal(t, 3600, windows[0].windowSec)
		assert.True(t, windows[0].aggregate)
	})

	t.Run("per-model match keys by rule slug", func(t *testing.T) {
		cfg := &config{
			PerModel: true,
			Rules: []budgetRule{
				{Model: "gpt-5", Max: 100, TimeWindow: "30m"},
			},
		}
		windows := windowsFor(cfg, base, "gpt-5")
		require.Len(t, windows, 1)
		assert.Equal(t, base+":model:gpt-5", windows[0].key)
		assert.Equal(t, float64(100), windows[0].max)
		assert.Equal(t, 1800, windows[0].windowSec)
		assert.False(t, windows[0].aggregate)
	})

	t.Run("per-model glob shares rule counter", func(t *testing.T) {
		cfg := &config{
			PerModel: true,
			Rules:    []budgetRule{{Model: "claude-opus-*", Max: 200, TimeWindow: "1h"}},
		}
		windows := windowsFor(cfg, base, "claude-opus-4")
		require.Len(t, windows, 1)
		assert.Equal(t, base+":model:claude-opus-*", windows[0].key)
	})

	t.Run("per-model and aggregate together", func(t *testing.T) {
		cfg := &config{
			PerModel:  true,
			Rules:     []budgetRule{{Model: "gpt-5", Max: 100, TimeWindow: "1h"}},
			Aggregate: &aggregateConfig{Max: 1000, TimeWindow: "1h"},
		}
		windows := windowsFor(cfg, base, "gpt-5")
		require.Len(t, windows, 2)
		primary := windows[primaryWindowIndex(windows)]
		assert.Equal(t, base, primary.key)
		assert.True(t, primary.aggregate)
	})

	t.Run("per-model no rule match yields no window", func(t *testing.T) {
		cfg := &config{
			PerModel: true,
			Rules:    []budgetRule{{Model: "gpt-5", Max: 100, TimeWindow: "1h"}},
		}
		windows := windowsFor(cfg, base, "gemini-2")
		assert.Empty(t, windows)
	})
}

func TestRuleWindowSeconds_FallsBackToLegacy(t *testing.T) {
	cfg := &config{Window: windowConfig{Unit: "day"}}
	assert.Equal(t, 86400, ruleWindowSeconds(cfg, budgetRule{Model: "gpt-5", Max: 1}))
	assert.Equal(t, 3600, ruleWindowSeconds(cfg, budgetRule{Model: "gpt-5", Max: 1, TimeWindow: "1h"}))
}

func TestAggregateWindowSeconds(t *testing.T) {
	assert.Equal(t, 1800, aggregateWindowSeconds(&config{Aggregate: &aggregateConfig{Max: 1, TimeWindow: "30m"}}))
	assert.Equal(t, 60, aggregateWindowSeconds(&config{Window: windowConfig{Unit: "minute"}, Aggregate: &aggregateConfig{Max: 1}}))
}

func TestCountedTokens(t *testing.T) {
	usage := &adapter.CanonicalUsage{InputTokens: 500, OutputTokens: 300, TotalTokens: 800}
	tests := []struct {
		name     string
		counting string
		usage    *adapter.CanonicalUsage
		want     int
	}{
		{name: "total", counting: countingTotal, usage: usage, want: 800},
		{name: "input", counting: countingInput, usage: usage, want: 500},
		{name: "output", counting: countingOutput, usage: usage, want: 300},
		{name: "nil usage", counting: countingTotal, usage: nil, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, countedTokens(tt.counting, tt.usage))
		})
	}
}

func TestValidate_FractionalTokenMaxRejected(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
	}{
		{
			name:     "aggregate fractional token max",
			settings: map[string]any{"aggregate": map[string]any{"max": 0.5, "time_window": "1m"}},
		},
		{
			name: "rule fractional token max",
			settings: map[string]any{
				"per_model": true,
				"rules":     []map[string]any{{"model": "gpt-5", "max": 1.5, "time_window": "1m"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			require.Error(t, err, "a fractional token max must be rejected so it cannot collapse to a phantom 0 limit")
		})
	}
}

func TestValidate_WholeTokenMaxAccepted(t *testing.T) {
	_, err := parseConfig(map[string]any{"aggregate": map[string]any{"max": 1, "time_window": "1m"}})
	require.NoError(t, err)
}

func TestValidate_FractionalDollarMaxAllowed(t *testing.T) {
	_, err := parseConfig(map[string]any{
		"unit":      "dollars",
		"aggregate": map[string]any{"max": 0.5, "time_window": "1m"},
	})
	require.NoError(t, err, "dollar budgets may be fractional")
}

func TestModelFor(t *testing.T) {
	t.Run("from body", func(t *testing.T) {
		req := &infracontext.RequestContext{Body: []byte(`{"model":"gpt-5"}`)}
		assert.Equal(t, "gpt-5", modelFor(req))
	})
	t.Run("from requested model when body has none", func(t *testing.T) {
		req := &infracontext.RequestContext{Body: []byte(`{"messages":[]}`), RequestedModel: "claude-opus-4"}
		assert.Equal(t, "claude-opus-4", modelFor(req))
	})
	t.Run("nil request", func(t *testing.T) {
		assert.Equal(t, "", modelFor(nil))
	})
}
