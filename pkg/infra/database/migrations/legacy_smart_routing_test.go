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

package migrations

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

func TestCanonicalLegacyLaddersPreserveAllCutsAndSinglePin(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, n := range []int{1, 4, 5} {
			t.Run(fmt.Sprintf("enabled=%t/n=%d", enabled, n), func(t *testing.T) {
				id := ids.New[ids.RegistryKind]()
				cfg := consumer.LBConfig{Enabled: enabled, Algorithm: algorithm.SmartRouting, PoolAlias: "preserved", SmartRouting: &registry.SmartRoutingConfig{}}
				policy := consumer.ModelPolicy{}
				for i, cut := range []float64{.72, .12, .97, .34, .55}[:n] {
					model := fmt.Sprintf("model-%d", i)
					cfg.Members = append(cfg.Members, consumer.LBPoolMember{RegistryID: id, Model: model})
					cfg.SmartRouting.Tiers = append(cfg.SmartRouting.Tiers, registry.SmartRoutingTier{RegistryID: id, Model: model, MinScore: cut})
					policy.Allowed = append(policy.Allowed, model)
				}
				raw := migrationTestJSON(t, cfg)
				policies := migrationTestJSON(t, consumer.ModelPolicies{id: policy})
				known := map[ids.RegistryID]struct{}{id: {}}
				got, err := canonicalSmartRoutingJSON(raw, policies, known)
				if err != nil {
					t.Fatal(err)
				}
				var migrated consumer.LBConfig
				if err := json.Unmarshal(got, &migrated); err != nil {
					t.Fatal(err)
				}
				if migrated.Enabled != enabled || migrated.PoolAlias != cfg.PoolAlias || !reflect.DeepEqual(migrated.Members, cfg.Members) {
					t.Fatal("migration changed enabled state or declared route pins")
				}
				if n == 1 {
					if migrated.SmartRouting != nil || migrated.Algorithm != algorithm.RoundRobin {
						t.Fatal("single route still requires scoring")
					}
				} else if !migrated.SmartRouting.LegacyThresholds || !reflect.DeepEqual(migrated.SmartRouting.Tiers, cfg.SmartRouting.Tiers) ||
					migrated.SmartRouting.SR1.CacheTTLSeconds != 300 || migrated.SmartRouting.SR1.EscapeHatchEnabled {
					t.Fatal("migration replaced a cut/model/order or changed policy defaults")
				}
				validation := migrated
				validation.Enabled = true
				if err := validation.Validate(consumer.ModelPolicies{id: policy}); err != nil {
					t.Fatal(err)
				}
				again, err := canonicalSmartRoutingJSON(got, policies, known)
				if err != nil || !equalRoutingJSON(got, again) {
					t.Fatalf("legacy migration not idempotent: %v", err)
				}
			})
		}
	}
}

func TestCanonicalSingleTierUsesItsRouteRatherThanFirstMember(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	raw := []byte(fmt.Sprintf(`{"enabled":true,"algorithm":"smart-routing","extension":"kept","members":[{"registry_id":%q,"model":"other"},{"registry_id":%q,"model":"chosen","extension":"member-kept"}],"smart_routing":{"tiers":[{"registry_id":%q,"model":"chosen","min_score":0.7}]}}`, id, id, id))
	policies := migrationTestJSON(t, consumer.ModelPolicies{id: {Allowed: []string{"other", "chosen"}}})
	got, err := canonicalSmartRoutingJSON(raw, policies, map[ids.RegistryID]struct{}{id: {}})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(got, &fields); err != nil {
		t.Fatal(err)
	}
	members := fields["members"].([]any)
	if len(members) != 1 || members[0].(map[string]any)["model"] != "chosen" || members[0].(map[string]any)["extension"] != "member-kept" || fields["extension"] != "kept" || fields["smart_routing"] != nil {
		t.Fatal("fixed conversion selected an undeclared route or dropped retained extensions")
	}
}
