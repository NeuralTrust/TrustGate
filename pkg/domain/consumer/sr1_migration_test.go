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
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

func TestSR1MigrationResolvesOnlyDeclaredConcretePins(t *testing.T) {
	low, high := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	for _, tc := range []struct {
		name        string
		member      LBPoolMember
		policy      ModelPolicy
		tierModel   string
		wantModel   string
		duplicate   bool
		wantInvalid bool
	}{
		{name: "explicit member", member: LBPoolMember{Model: "low"}, wantModel: "low"},
		{name: "singleton member", member: LBPoolMember{Models: []string{"low"}}, wantModel: "low"},
		{name: "explicit default within pool", member: LBPoolMember{Models: []string{"other", "low"}}, policy: ModelPolicy{Allowed: []string{"other", "low"}, Default: "low"}, wantModel: "low"},
		{name: "explicit default without member allow-list", policy: ModelPolicy{Allowed: []string{"low"}, Default: "low"}, wantModel: "low"},
		{name: "explicit tier resolved to singleton member", member: LBPoolMember{Models: []string{"low"}}, tierModel: "low", wantModel: "low"},
		{name: "multiple models without default", member: LBPoolMember{Models: []string{"first", "second"}}, wantInvalid: true},
		{name: "default outside pool", member: LBPoolMember{Models: []string{"first", "second"}}, policy: ModelPolicy{Default: "outside"}, wantInvalid: true},
		{name: "default outside policy", member: LBPoolMember{Models: []string{"low", "other"}}, policy: ModelPolicy{Allowed: []string{"other"}, Default: "low"}, wantInvalid: true},
		{name: "wildcard singleton", member: LBPoolMember{Models: []string{"model-*"}}, wantInvalid: true},
		{name: "repeated registry without tier pin", member: LBPoolMember{Model: "low"}, duplicate: true, wantInvalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			member := tc.member
			member.RegistryID = low
			cfg := &LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
				Members: []LBPoolMember{member, {RegistryID: high, Model: "high"}},
				SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{
					{RegistryID: high, Model: "high", MinScore: .8},
					{RegistryID: low, Model: tc.tierModel, MinScore: .1},
				}},
			}
			if tc.duplicate {
				cfg.Members = append(cfg.Members, LBPoolMember{RegistryID: low, Model: "other"})
			}
			originalTiers := append([]registry.SmartRoutingTier(nil), cfg.SmartRouting.Tiers...)
			originalMembers := append([]LBPoolMember(nil), cfg.Members...)
			got, err := cfg.NormalizeSmartRouting(ModelPolicies{low: tc.policy})
			if !reflect.DeepEqual(originalTiers, cfg.SmartRouting.Tiers) || !reflect.DeepEqual(originalMembers, cfg.Members) || cfg.SmartRouting.SR1 != nil {
				t.Fatal("normalization mutated the historical input")
			}
			if tc.wantInvalid {
				if err == nil {
					t.Fatal("ambiguous or invalid route was guessed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Members) != len(cfg.Members) || len(got.SmartRouting.Tiers) != 2 {
				t.Fatal("migration discarded declared routes")
			}
			if got.SmartRouting.Tiers[0].RegistryID != low || got.SmartRouting.Tiers[0].Model != tc.wantModel || got.SmartRouting.Tiers[0].MinScore != 0 || got.SmartRouting.Tiers[1].RegistryID != high || got.SmartRouting.Tiers[1].Model != "high" || got.SmartRouting.Tiers[1].MinScore != .45 {
				t.Fatalf("sorted route order or fixed cuts changed: %+v", got.SmartRouting.Tiers)
			}
			if got.Members[0].Model != tc.wantModel || got.SmartRouting.SR1.EscapeHatchEnabled == nil || got.SmartRouting.SR1.EscapeEnabled() || got.SmartRouting.SR1.CacheTTLSeconds != 300 {
				t.Fatalf("incorrect migrated member or default policy: %+v", got)
			}
		})
	}
}

func TestSR1HistoricalFlagReadCompatibilityAndTTL(t *testing.T) {
	id := ids.New[ids.RegistryKind]().String()
	for _, tc := range []struct {
		name, field string
		want        bool
	}{
		{"historical omission", "", true},
		{"explicit off", `,"escape_hatch_enabled":false`, false},
		{"explicit on", `,"escape_hatch_enabled":true`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"lb_config":{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"model":"low"},{"registry_id":%q,"model":"high"}],"smart_routing":{"sr1":{"cache_ttl_seconds":86400%s},"tiers":[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]}}}`, id, id, tc.field, id, id))
			var c Consumer
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			flag := c.LBConfig.SmartRouting.SR1.EscapeHatchEnabled
			if flag == nil || *flag != tc.want || c.LBConfig.SmartRouting.SR1.CacheTTLSeconds != 86400 {
				t.Fatalf("historical preference or TTL lost: %+v", c.LBConfig.SmartRouting.SR1)
			}
			encoded, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			var again Consumer
			if err := json.Unmarshal(encoded, &again); err != nil || again.LBConfig.SmartRouting.SR1.EscapeEnabled() != tc.want {
				t.Fatalf("round trip changed historical preference: %v", err)
			}
		})
	}
	for _, field := range []string{"escape_hatch_enabled", "ESCAPE_HATCH_ENABLED"} {
		var c Consumer
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"lb_config":{"smart_routing":{"sr1":{"cache_ttl_seconds":300,%q:null}}}}`, field)), &c); err == nil {
			t.Fatal("stored null preference was treated as historical omission")
		}
	}
}
