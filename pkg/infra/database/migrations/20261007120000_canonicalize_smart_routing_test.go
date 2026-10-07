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

func TestCanonicalSmartRoutingJSONResolvesOnlyDeclaredPins(t *testing.T) {
	low, high := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	known := map[ids.RegistryID]struct{}{low: {}, high: {}}
	for _, tc := range []struct {
		name                   string
		member                 consumer.LBPoolMember
		policy                 consumer.ModelPolicy
		tierModel              string
		wantModel              string
		duplicate, wantInvalid bool
	}{
		{name: "explicit member", member: consumer.LBPoolMember{Model: "low"}, policy: consumer.ModelPolicy{Allowed: []string{"low"}}, wantModel: "low"},
		{name: "singleton member", member: consumer.LBPoolMember{Models: []string{"low"}}, policy: consumer.ModelPolicy{Allowed: []string{"low"}}, wantModel: "low"},
		{name: "explicit default within pool", member: consumer.LBPoolMember{Models: []string{"other", "low"}}, policy: consumer.ModelPolicy{Allowed: []string{"other", "low"}, Default: "low"}, wantModel: "low"},
		{name: "default without member list", policy: consumer.ModelPolicy{Allowed: []string{"low"}, Default: "low"}, wantModel: "low"},
		{name: "explicit tier and singleton member", member: consumer.LBPoolMember{Models: []string{"low"}}, policy: consumer.ModelPolicy{Allowed: []string{"low"}}, tierModel: "low", wantModel: "low"},
		{name: "multiple models without default", member: consumer.LBPoolMember{Models: []string{"first", "second"}}, wantInvalid: true},
		{name: "default outside pool", member: consumer.LBPoolMember{Models: []string{"first", "second"}}, policy: consumer.ModelPolicy{Default: "outside"}, wantInvalid: true},
		{name: "default outside policy", member: consumer.LBPoolMember{Models: []string{"low", "other"}}, policy: consumer.ModelPolicy{Allowed: []string{"other"}, Default: "low"}, wantInvalid: true},
		{name: "wildcard singleton", member: consumer.LBPoolMember{Models: []string{"model-*"}}, wantInvalid: true},
		{name: "repeated registry without tier pin", member: consumer.LBPoolMember{Model: "low"}, duplicate: true, wantInvalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			member := tc.member
			member.RegistryID = low
			cfg := &consumer.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting,
				Members:      []consumer.LBPoolMember{member, {RegistryID: high, Model: "high"}},
				SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{{RegistryID: high, Model: "high", MinScore: .8}, {RegistryID: low, Model: tc.tierModel, MinScore: .1}}},
			}
			if tc.duplicate {
				cfg.Members = append(cfg.Members, consumer.LBPoolMember{RegistryID: low, Model: "other"})
			}
			raw := migrationTestJSON(t, cfg)
			before := string(raw)
			policies := migrationTestJSON(t, consumer.ModelPolicies{low: tc.policy, high: {Allowed: []string{"high"}}})
			got, err := canonicalSmartRoutingJSON(raw, policies, known)
			if string(raw) != before {
				t.Fatal("planner changed original evidence")
			}
			if tc.wantInvalid {
				if err == nil {
					t.Fatal("ambiguous route was guessed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var migrated consumer.LBConfig
			if err := json.Unmarshal(got, &migrated); err != nil {
				t.Fatal(err)
			}
			if len(migrated.Members) != len(cfg.Members) || len(migrated.SmartRouting.Tiers) != 2 {
				t.Fatal("declared routes discarded")
			}
			if migrated.SmartRouting.Tiers[0].RegistryID != high || migrated.SmartRouting.Tiers[0].MinScore != .45 || migrated.SmartRouting.Tiers[1].RegistryID != low || migrated.SmartRouting.Tiers[1].MinScore != 0 {
				t.Fatal("array order or score rank changed")
			}
			if migrated.Members[0].Model != tc.wantModel || migrated.SmartRouting.Tiers[1].Model != tc.wantModel || migrated.SmartRouting.SR1.EscapeHatchEnabled || migrated.SmartRouting.SR1.CacheTTLSeconds != 300 {
				t.Fatal("incorrect pins or legacy defaults")
			}
			again, err := canonicalSmartRoutingJSON(got, policies, known)
			if err != nil || !equalRoutingJSON(got, again) {
				t.Fatalf("canonical planner is not idempotent: %v", err)
			}
		})
	}
}

func TestCanonicalSmartRoutingJSONHistoricalFlags(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	known := map[ids.RegistryID]struct{}{id: {}}
	policies := migrationTestJSON(t, consumer.ModelPolicies{id: {Allowed: []string{"low", "high"}}})
	for _, tc := range []struct {
		name, field string
		want        bool
		invalid     bool
	}{
		{"historical omission", "", true, false},
		{"explicit off", `,"escape_hatch_enabled":false`, false, false},
		{"explicit on", `,"escape_hatch_enabled":true`, true, false},
		{"null", `,"escape_hatch_enabled":null`, false, true},
		{"uppercase null", `,"ESCAPE_HATCH_ENABLED":null`, false, true},
		{"conflicting flag aliases", `,"escape_hatch_enabled":false,"ESCAPE_HATCH_ENABLED":true`, false, true},
		{"conflicting lifetime aliases", `,"CACHE_TTL_SECONDS":30`, false, true},
		{"string", `,"escape_hatch_enabled":"false"`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"model":"low"},{"registry_id":%q,"model":"high"}],"extension":{"value":1},"smart_routing":{"sr1":{"cache_ttl_seconds":86400%s,"extension":"kept"},"tiers":[{"min_score":0,"registry_id":%q,"model":"low","extension":"kept"},{"min_score":0.45,"registry_id":%q,"model":"high"}]}}`, id, id, tc.field, id, id))
			got, err := canonicalSmartRoutingJSON(raw, policies, known)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid historical flag accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var migrated consumer.LBConfig
			if err := json.Unmarshal(got, &migrated); err != nil {
				t.Fatal(err)
			}
			if migrated.SmartRouting.SR1.EscapeHatchEnabled != tc.want || migrated.SmartRouting.SR1.CacheTTLSeconds != 86400 {
				t.Fatal("historical flag or lifetime changed")
			}
			var fields map[string]any
			if err := json.Unmarshal(got, &fields); err != nil {
				t.Fatal(err)
			}
			smart := fields["smart_routing"].(map[string]any)
			if fields["extension"] == nil || smart["sr1"].(map[string]any)["extension"] != "kept" || smart["tiers"].([]any)[0].(map[string]any)["extension"] != "kept" {
				t.Fatal("unrelated metadata lost")
			}
		})
	}
}

func TestCanonicalSmartRoutingJSONRejectsUnresolvedEnabledAndDisabled(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	policies := migrationTestJSON(t, consumer.ModelPolicies{id: {Allowed: []string{"low", "high"}}})
	for _, enabled := range []bool{true, false} {
		for _, n := range []int{1, 4} {
			cfg := consumer.LBConfig{Enabled: enabled, Algorithm: algorithm.SmartRouting, Members: []consumer.LBPoolMember{{RegistryID: id, Model: "low"}, {RegistryID: id, Model: "high"}}, SmartRouting: &registry.SmartRoutingConfig{}}
			for i := 0; i < n; i++ {
				cfg.SmartRouting.Tiers = append(cfg.SmartRouting.Tiers, registry.SmartRoutingTier{RegistryID: id, Model: "low", MinScore: float64(i) / 10})
			}
			raw := migrationTestJSON(t, cfg)
			if _, err := canonicalSmartRoutingJSON(raw, policies, map[ids.RegistryID]struct{}{id: {}}); err == nil {
				t.Fatalf("enabled=%t n=%d: unsupported data was discarded or rebuilt", enabled, n)
			}
		}
	}
	cfg := consumer.LBConfig{Enabled: true, Algorithm: algorithm.SmartRouting, Members: []consumer.LBPoolMember{{RegistryID: id, Model: "low"}, {RegistryID: id, Model: "high"}}, SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{{RegistryID: id, Model: "low", MinScore: 0}, {RegistryID: id, Model: "high", MinScore: .8}}}}
	if _, err := canonicalSmartRoutingJSON(migrationTestJSON(t, cfg), policies, nil); err == nil {
		t.Fatal("missing registry references accepted")
	}
	cfg.SmartRouting.SR1 = &registry.SR1Config{CacheTTLSeconds: 30}
	if _, err := canonicalSmartRoutingJSON(migrationTestJSON(t, cfg), policies, map[ids.RegistryID]struct{}{id: {}}); err == nil {
		t.Fatal("custom explicit commitment cuts silently rewritten")
	}
}

func migrationTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEqualRoutingJSONUsesSemanticValues(t *testing.T) {
	if !equalRoutingJSON([]byte(`{"a":1,"b":false}`), []byte(`{"b":false,"a":1.0}`)) || equalRoutingJSON([]byte(`{"a":1}`), []byte(`{"a":2}`)) {
		t.Fatal("semantic equality is incorrect")
	}
	if reflect.DeepEqual([]byte(`{"a":1}`), []byte(`{"a":1.0}`)) {
		t.Fatal("fixture does not differ in representation")
	}
}
