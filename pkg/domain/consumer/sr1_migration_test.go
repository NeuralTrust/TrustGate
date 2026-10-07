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

func TestSR1SerializationDoesNotMigrateHistoricalData(t *testing.T) {
	id := ids.New[ids.RegistryKind]().String()
	for _, envelope := range []string{"", `"sr1":{"cache_ttl_seconds":30},`} {
		raw := []byte(fmt.Sprintf(`{"lb_config":{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"models":["low"]},{"registry_id":%q,"model":"high"}],"smart_routing":{%s"tiers":[{"min_score":0.8,"registry_id":%q,"model":"high"},{"min_score":0.1,"registry_id":%q}]}}}`, id, id, envelope, id, id))
		var c Consumer
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		before := c.LBConfig
		if before.SmartRouting.Tiers[0].MinScore != .8 || before.SmartRouting.Tiers[1].Model != "" || before.Members[0].Model != "" {
			t.Fatal("read path migrated historical routes")
		}
		if before.SmartRouting.SR1 != nil && before.SmartRouting.SR1.EscapeHatchEnabled {
			t.Fatal("domain JSON treats omitted preference as true")
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var again Consumer
		if err := json.Unmarshal(encoded, &again); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, again.LBConfig) {
			t.Fatal("serialization changed historical routing")
		}
	}
}

func TestLBConfigValidateDoesNotMutate(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	for _, tc := range []struct {
		name      string
		enabled   bool
		algorithm string
		cuts      []float64
		wantError bool
	}{
		{"canonical unordered", true, algorithm.SmartRouting, []float64{.45, 0}, false},
		{"custom thresholds", true, algorithm.SmartRouting, []float64{.8, .1}, true},
		{"disabled legacy", false, algorithm.SmartRouting, []float64{.9}, false},
		{"implicit round robin", true, "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &LBConfig{Enabled: tc.enabled, Algorithm: tc.algorithm, Members: []LBPoolMember{{RegistryID: id, Model: "low"}, {RegistryID: id, Model: "high"}}}
			if tc.cuts != nil {
				cfg.SmartRouting = &registry.SmartRoutingConfig{SR1: &registry.SR1Config{CacheTTLSeconds: 30}, Tiers: []registry.SmartRoutingTier{}}
				for i, cut := range tc.cuts {
					cfg.SmartRouting.Tiers = append(cfg.SmartRouting.Tiers, registry.SmartRoutingTier{RegistryID: id, Model: []string{"high", "low"}[i], MinScore: cut})
				}
			}
			before, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = cfg.Validate(ModelPolicies{id: {Allowed: []string{"low", "high"}}})
			if (err != nil) != tc.wantError {
				t.Fatalf("Validate error=%v wantError=%t", err, tc.wantError)
			}
			after, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("validation mutated its receiver")
			}
		})
	}
}

func TestConsumerDisabledLegacyPoolAllowsUnrelatedEdits(t *testing.T) {
	attached, unknown := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	cfg := &LBConfig{Algorithm: algorithm.SmartRouting, SmartRouting: &registry.SmartRoutingConfig{Tiers: []registry.SmartRoutingTier{{RegistryID: unknown, MinScore: .9}}}}
	c, err := New(CreateParams{GatewayID: ids.New[ids.GatewayKind](), Name: "legacy", Type: TypeLLM, RegistryIDs: []ids.RegistryID{attached}, ModelPolicies: ModelPolicies{attached: {Allowed: []string{"low"}}}, LBConfig: cfg})
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "updated"
	c.Headers = map[string]string{"x-example": "value"}
	if err := c.Validate(); err != nil {
		t.Fatalf("unrelated edit rejected: %v", err)
	}
	after, err := json.Marshal(c.LBConfig)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("disabled legacy policy changed during edit")
	}
}
