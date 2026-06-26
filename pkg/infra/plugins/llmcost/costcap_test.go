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

package llmcost

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvaluateCeiling(t *testing.T) {
	cc := &CapConfig{
		MaxInputCostPer1k:  1,
		MaxOutputCostPer1k: 2,
		PerModelOverrides: map[string]Ceiling{
			"claude-opus-*": {MaxInputCostPer1k: 10, MaxOutputCostPer1k: 20},
			"claude-opus-4": {MaxInputCostPer1k: 30, MaxOutputCostPer1k: 40},
		},
	}
	t.Run("falls back to global", func(t *testing.T) {
		c := EvaluateCeiling(cc, "gpt-4o")
		assert.Equal(t, float64(1), c.MaxInputCostPer1k)
		assert.Equal(t, float64(2), c.MaxOutputCostPer1k)
	})
	t.Run("glob override applies", func(t *testing.T) {
		c := EvaluateCeiling(cc, "claude-opus-3")
		assert.Equal(t, float64(10), c.MaxInputCostPer1k)
	})
	t.Run("exact beats glob", func(t *testing.T) {
		c := EvaluateCeiling(cc, "claude-opus-4")
		assert.Equal(t, float64(30), c.MaxInputCostPer1k)
		assert.Equal(t, float64(40), c.MaxOutputCostPer1k)
	})
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name         string
		costCap      *CapConfig
		pricing      map[string]CustomPrice
		model        string
		wantKind     DecisionKind
		wantUnknown  bool
		wantMaxInput float64
	}{
		{
			name:         "under global ceiling allows",
			costCap:      &CapConfig{Enabled: true, MaxInputCostPer1k: 5, MaxOutputCostPer1k: 5},
			pricing:      map[string]CustomPrice{"gpt-4o": {Input: 0.001, Output: 0.001}},
			model:        "gpt-4o",
			wantKind:     DecisionAllow,
			wantMaxInput: 5,
		},
		{
			name:         "over global input ceiling violates",
			costCap:      &CapConfig{Enabled: true, MaxInputCostPer1k: 0.5, MaxOutputCostPer1k: 5},
			pricing:      map[string]CustomPrice{"gpt-4o": {Input: 0.001, Output: 0.001}},
			model:        "gpt-4o",
			wantKind:     DecisionViolation,
			wantMaxInput: 0.5,
		},
		{
			name: "per-model override raises ceiling and allows",
			costCap: &CapConfig{
				Enabled:            true,
				MaxInputCostPer1k:  0.5,
				MaxOutputCostPer1k: 0.5,
				PerModelOverrides:  map[string]Ceiling{"claude-opus-*": {MaxInputCostPer1k: 100, MaxOutputCostPer1k: 100}},
			},
			pricing:      map[string]CustomPrice{"claude-opus-4": {Input: 0.001, Output: 0.001}},
			model:        "claude-opus-4",
			wantKind:     DecisionAllow,
			wantMaxInput: 100,
		},
		{
			name: "dated model resolves base-slug override not global",
			costCap: &CapConfig{
				Enabled:            true,
				MaxInputCostPer1k:  0.5,
				MaxOutputCostPer1k: 0.5,
				PerModelOverrides:  map[string]Ceiling{"gpt-4o": {MaxInputCostPer1k: 100, MaxOutputCostPer1k: 100}},
			},
			pricing:      map[string]CustomPrice{"gpt-4o": {Input: 0.001, Output: 0.001}},
			model:        "gpt-4o-2024-08-06",
			wantKind:     DecisionAllow,
			wantMaxInput: 100,
		},
		{
			name:         "unknown reject violates",
			costCap:      &CapConfig{Enabled: true, MaxInputCostPer1k: 1, UnknownModel: UnknownReject},
			model:        "mystery",
			wantKind:     DecisionViolation,
			wantUnknown:  true,
			wantMaxInput: 1,
		},
		{
			name:         "unknown assume_max violates",
			costCap:      &CapConfig{Enabled: true, MaxInputCostPer1k: 1, UnknownModel: UnknownAssumeMax},
			model:        "mystery",
			wantKind:     DecisionViolation,
			wantUnknown:  true,
			wantMaxInput: 1,
		},
		{
			name:         "unknown pass_through allows",
			costCap:      &CapConfig{Enabled: true, MaxInputCostPer1k: 1, UnknownModel: UnknownPassThrough},
			model:        "mystery",
			wantKind:     DecisionAllow,
			wantUnknown:  true,
			wantMaxInput: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := Decide(context.Background(), nil, tt.pricing, tt.costCap, "openai", tt.model)
			assert.Equal(t, tt.wantKind, dec.Kind)
			assert.Equal(t, tt.wantUnknown, dec.Unknown)
			assert.Equal(t, tt.model, dec.Model)
			assert.Equal(t, tt.wantMaxInput, dec.MaxInput)
		})
	}
}
