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

package registry

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestSmartRoutingConfig_TierForScore_SameRegistryDifferentModels(t *testing.T) {
	t.Parallel()
	reg := ids.New[ids.RegistryKind]()
	cfg := &SmartRoutingConfig{
		Tiers: []SmartRoutingTier{
			{MinScore: 0, RegistryID: reg, Model: "gpt-4o-mini"},
			{MinScore: 0.3, RegistryID: reg, Model: "gpt-4.1-mini"},
			{MinScore: 0.8, RegistryID: reg, Model: "gpt-5.6-luna"},
		},
	}

	cases := []struct {
		score float64
		model string
	}{
		{0.1, "gpt-4o-mini"},
		{0.5, "gpt-4.1-mini"},
		{0.9, "gpt-5.6-luna"},
	}
	for _, tc := range cases {
		tier, ok := cfg.TierForScore(tc.score)
		if !ok {
			t.Fatalf("score %g: expected a tier", tc.score)
		}
		if tier.RegistryID != reg {
			t.Fatalf("score %g: registry = %s, want %s", tc.score, tier.RegistryID, reg)
		}
		model, ok := cfg.ModelForScore(tc.score)
		if !ok || model != tc.model {
			t.Fatalf("score %g: model = %q ok=%v, want %q", tc.score, model, ok, tc.model)
		}
	}
}

func TestSmartRoutingConfig_ModelForScore_EmptyWhenUnset(t *testing.T) {
	t.Parallel()
	reg := ids.New[ids.RegistryKind]()
	cfg := &SmartRoutingConfig{
		Tiers: []SmartRoutingTier{
			{MinScore: 0, RegistryID: reg},
		},
	}
	if model, ok := cfg.ModelForScore(0.2); ok || model != "" {
		t.Fatalf("expected no model override, got %q ok=%v", model, ok)
	}
}
