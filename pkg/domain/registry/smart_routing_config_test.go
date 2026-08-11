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

func TestSmartRoutingConfig_TierForScore(t *testing.T) {
	t.Parallel()
	shared := ids.New[ids.RegistryKind]()
	cfg := &SmartRoutingConfig{
		Tiers: []SmartRoutingTier{
			{MinScore: 0, RegistryID: shared, Model: "gpt-4o-mini"},
			{MinScore: 0.3, RegistryID: shared, Model: "gpt-4.1-mini"},
			{MinScore: 0.8, RegistryID: shared, Model: "gpt-5"},
		},
	}
	tests := []struct {
		name  string
		score float64
		want  string
	}{
		{name: "lowest tier", score: 0.1, want: "gpt-4o-mini"},
		{name: "at a threshold", score: 0.3, want: "gpt-4.1-mini"},
		{name: "between thresholds", score: 0.5, want: "gpt-4.1-mini"},
		{name: "highest tier", score: 0.9, want: "gpt-5"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tier, ok := cfg.TierForScore(tc.score)
			if !ok {
				t.Fatalf("score %g: expected a tier", tc.score)
			}
			if tier.RegistryID != shared {
				t.Fatalf("score %g: registry = %s, want %s", tc.score, tier.RegistryID, shared)
			}
			if got := tier.RouteModel(); got != tc.want {
				t.Fatalf("score %g: model = %q, want %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestSmartRoutingConfig_TierForScoreBelowEveryThreshold(t *testing.T) {
	t.Parallel()
	cfg := &SmartRoutingConfig{
		Tiers: []SmartRoutingTier{
			{MinScore: 0.4, RegistryID: ids.New[ids.RegistryKind]()},
		},
	}
	if _, ok := cfg.TierForScore(0.1); ok {
		t.Fatal("expected no tier for a score below every threshold")
	}
}

func TestSmartRoutingTier_RouteModelTrimsBlanks(t *testing.T) {
	t.Parallel()
	if got := (SmartRoutingTier{Model: "  gpt-5  "}).RouteModel(); got != "gpt-5" {
		t.Fatalf("RouteModel() = %q, want %q", got, "gpt-5")
	}
	if got := (SmartRoutingTier{Model: "   "}).RouteModel(); got != "" {
		t.Fatalf("RouteModel() = %q, want empty", got)
	}
}
