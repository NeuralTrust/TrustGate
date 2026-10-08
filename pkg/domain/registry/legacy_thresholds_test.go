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
	"encoding/json"
	"math"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestLegacyThresholdsValidationIsExplicitAndPure(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	for _, cuts := range [][]float64{{.12, .34, .72, .97}, {.34, .72, .97}, {.72, .97}} {
		cfg := &SmartRoutingConfig{SR1: &SR1Config{CacheTTLSeconds: 300, EscapeHatchEnabled: true}}
		for i, cut := range cuts {
			cfg.Tiers = append(cfg.Tiers, SmartRoutingTier{MinScore: cut, RegistryID: id, Model: string(rune('a' + i))})
		}
		if cfg.Validate() == nil {
			t.Fatal("ordinary creation accepts retained thresholds")
		}
		cfg.LegacyThresholds = true
		before, _ := json.Marshal(cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		after, _ := json.Marshal(cfg)
		if string(before) != string(after) {
			t.Fatal("validation rewrites a retained ladder")
		}
	}
	for _, cuts := range [][]float64{{.2}, {.2, .2}, {-.1, .2}, {.2, 1.1}, {.2, math.NaN()}, {.2, math.Inf(1)}} {
		cfg := &SmartRoutingConfig{LegacyThresholds: true, SR1: &SR1Config{CacheTTLSeconds: 300}}
		for i, cut := range cuts {
			cfg.Tiers = append(cfg.Tiers, SmartRoutingTier{MinScore: cut, RegistryID: id, Model: string(rune('a' + i))})
		}
		if cfg.Validate() == nil {
			t.Fatalf("invalid retained cuts accepted: %v", cuts)
		}
	}
}
