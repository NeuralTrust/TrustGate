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

package request

import (
	"encoding/json"
	"fmt"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestSR1HTTPConfigPreservedOnCreateAndUpdate(t *testing.T) {
	id := ids.New[ids.RegistryKind]().String()
	raw := []byte(fmt.Sprintf(`{"lb_config":{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"model":"low"},{"registry_id":%q,"model":"high"}],"smart_routing":{"sr1":{"cache_ttl_seconds":30,"escape_hatch_enabled":true},"tiers":[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]}}}`, id, id, id, id))
	var create CreateConsumerRequest
	var update UpdateConsumerRequest
	if err := json.Unmarshal(raw, &create); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &update); err != nil {
		t.Fatal(err)
	}
	c, err := create.ToLBConfig()
	if err != nil {
		t.Fatal(err)
	}
	u, err := update.ToLBConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []*LBConfigRequest{create.LBConfig, update.LBConfig} {
		if cfg.SmartRouting.SR1 == nil || cfg.SmartRouting.SR1.CacheTTLSeconds != 30 {
			t.Fatal("JSON SR1 dropped")
		}
	}
	if c.SmartRouting.SR1 == nil || u.SmartRouting.SR1 == nil || c.SmartRouting.SR1.CacheTTLSeconds != 30 || u.SmartRouting.SR1.CacheTTLSeconds != 30 || !c.SmartRouting.SR1.EscapeEnabled() || !u.SmartRouting.SR1.EscapeEnabled() {
		t.Fatal("domain conversion dropped SR1")
	}
	c.SmartRouting.SR1.CacheTTLSeconds = 0
	if c.Validate(nil) == nil {
		t.Fatal("invalid SR1 TTL accepted")
	}
}

func TestSR1HTTPNewWritePreferenceDefaults(t *testing.T) {
	registryID := ids.New[ids.RegistryKind]()
	id := registryID.String()
	policies := consumerdomain.ModelPolicies{registryID: {Allowed: []string{"low", "high"}}}
	for _, tc := range []struct {
		name, envelope string
		want           bool
	}{
		{"no envelope", "", false},
		{"omitted flag", `"sr1":{"cache_ttl_seconds":30},`, false},
		{"explicit false", `"sr1":{"cache_ttl_seconds":30,"escape_hatch_enabled":false},`, false},
		{"explicit true", `"sr1":{"cache_ttl_seconds":30,"escape_hatch_enabled":true},`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"lb_config":{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"model":"low"},{"registry_id":%q,"model":"high"}],"smart_routing":{%s"tiers":[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]}}}`, id, id, tc.envelope, id, id))
			var create CreateConsumerRequest
			var update UpdateConsumerRequest
			if err := json.Unmarshal(raw, &create); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &update); err != nil {
				t.Fatal(err)
			}
			for _, wire := range []*LBConfigRequest{create.LBConfig, update.LBConfig} {
				cfg, err := wire.ToDomain()
				if err != nil {
					t.Fatal(err)
				}
				if err := cfg.Validate(policies); err != nil {
					t.Fatal(err)
				}
				flag := cfg.SmartRouting.SR1.EscapeHatchEnabled
				if flag != tc.want {
					t.Fatalf("new write flag=%v want explicit %t", flag, tc.want)
				}
				wantTTL := 30
				if tc.envelope == "" {
					wantTTL = 300
				}
				if cfg.SmartRouting.SR1.CacheTTLSeconds != wantTTL {
					t.Fatalf("TTL=%d want=%d", cfg.SmartRouting.SR1.CacheTTLSeconds, wantTTL)
				}
			}
		})
	}
}

func TestSR1HTTPRejectsNonBooleanPreference(t *testing.T) {
	for _, field := range []string{"escape_hatch_enabled", "ESCAPE_HATCH_ENABLED"} {
		for _, literal := range []string{"null", "1", `"false"`, "[]", "{}"} {
			t.Run(field+"="+literal, func(t *testing.T) {
				raw := []byte(fmt.Sprintf(`{"lb_config":{"smart_routing":{"sr1":{"cache_ttl_seconds":30,%q:%s}}}}`, field, literal))
				var create CreateConsumerRequest
				var update UpdateConsumerRequest
				if err := json.Unmarshal(raw, &create); err == nil {
					t.Fatal("create accepted a nonboolean preference")
				}
				if err := json.Unmarshal(raw, &update); err == nil {
					t.Fatal("update accepted a nonboolean preference")
				}
			})
		}
	}
}

func TestSR1HTTPDisabledExplicitWritesRequireCanonicalConfig(t *testing.T) {
	id := ids.New[ids.RegistryKind]().String()
	other := ids.New[ids.RegistryKind]().String()
	for _, tc := range []struct {
		name, tiers, extra string
		wantError          bool
	}{
		{"canonical", fmt.Sprintf(`[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]`, id, id), `"sr1":{"cache_ttl_seconds":30},`, false},
		{"one rung", fmt.Sprintf(`[{"min_score":0,"registry_id":%q,"model":"low"}]`, id), "", true},
		{"custom cuts", fmt.Sprintf(`[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.8,"registry_id":%q,"model":"high"}]`, id, id), "", true},
		{"pattern pin", fmt.Sprintf(`[{"min_score":0,"registry_id":%q,"model":"model-*"},{"min_score":0.45,"registry_id":%q,"model":"high"}]`, id, id), "", true},
		{"nonmember registry", fmt.Sprintf(`[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]`, other, id), "", true},
		{"invalid lifetime", fmt.Sprintf(`[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]`, id, id), `"sr1":{"cache_ttl_seconds":0},`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"lb_config":{"enabled":false,"algorithm":"smart-routing","members":[{"registry_id":%q,"model":"low"},{"registry_id":%q,"model":"high"}],"smart_routing":{%s"tiers":%s}}}`, id, id, tc.extra, tc.tiers))
			var create CreateConsumerRequest
			var update UpdateConsumerRequest
			if err := json.Unmarshal(raw, &create); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &update); err != nil {
				t.Fatal(err)
			}
			for _, wire := range []*LBConfigRequest{create.LBConfig, update.LBConfig} {
				got, err := wire.ToDomain()
				if (err != nil) != tc.wantError {
					t.Fatalf("conversion error=%v wantError=%t", err, tc.wantError)
				}
				if err == nil && (got.Enabled || wire.Enabled) {
					t.Fatal("ingress validation enabled a disabled pool")
				}
			}
		})
	}
	var omitted UpdateConsumerRequest
	if err := json.Unmarshal([]byte(`{"name":"updated"}`), &omitted); err != nil {
		t.Fatal(err)
	}
	if cfg, err := omitted.ToLBConfig(); err != nil || cfg != nil {
		t.Fatal("omitted legacy config was validated or changed")
	}
}
