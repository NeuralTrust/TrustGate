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

package consumer

import (
	"reflect"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

func TestLegacyRegistryPruningRetainsCutsThenPinsSoleSurvivor(t *testing.T) {
	c := &Consumer{ModelPolicies: ModelPolicies{}, LBConfig: &LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
		SmartRouting: &registry.SmartRoutingConfig{LegacyThresholds: true, SR1: &registry.SR1Config{CacheTTLSeconds: 123, EscapeHatchEnabled: true}}}}
	for i, cut := range []float64{.12, .34, .72, .97} {
		id := ids.New[ids.RegistryKind]()
		model := string(rune('a' + i))
		c.ModelPolicies[id] = ModelPolicy{Allowed: []string{model}}
		c.LBConfig.Members = append(c.LBConfig.Members, LBPoolMember{RegistryID: id, Model: model})
		c.LBConfig.SmartRouting.Tiers = append(c.LBConfig.SmartRouting.Tiers, registry.SmartRoutingTier{RegistryID: id, Model: model, MinScore: cut})
	}
	for remaining := 3; remaining >= 1; remaining-- {
		original := append([]registry.SmartRoutingTier(nil), c.LBConfig.SmartRouting.Tiers...)
		if _, changed := c.PruneRegistry(original[0].RegistryID); !changed {
			t.Fatal("referenced registry was not pruned")
		}
		if err := c.LBConfig.Validate(c.ModelPolicies); err != nil {
			t.Fatalf("remaining=%d invalid survivor: %v", remaining, err)
		}
		if remaining == 1 {
			if c.LBConfig.SmartRouting != nil || c.LBConfig.Algorithm != algorithm.RoundRobin || len(c.LBConfig.Members) != 1 ||
				c.LBConfig.Members[0].RegistryID != original[1].RegistryID || c.LBConfig.Members[0].Model != original[1].Model {
				t.Fatal("sole survivor is not the fixed declared route")
			}
			continue
		}
		cfg := c.LBConfig.SmartRouting
		if !cfg.LegacyThresholds || !reflect.DeepEqual(cfg.Tiers, original[1:]) || cfg.SR1.CacheTTLSeconds != 123 || !cfg.SR1.EscapeHatchEnabled {
			t.Fatal("pruning replaced retained cuts, routes or policy settings")
		}
	}
}
