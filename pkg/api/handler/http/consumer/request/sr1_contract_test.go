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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"testing"
)

func TestSR1HTTPConfigPreservedOnCreateAndUpdate(t *testing.T) {
	id := ids.New[ids.RegistryKind]().String()
	raw := []byte(fmt.Sprintf(`{"lb_config":{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"model":"low"},{"registry_id":%q,"model":"high"}],"smart_routing":{"sr1":{"cache_ttl_seconds":30},"tiers":[{"min_score":0,"registry_id":%q,"model":"low"},{"min_score":0.45,"registry_id":%q,"model":"high"}]}}}`, id, id, id, id))
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
	if c.SmartRouting.SR1 == nil || u.SmartRouting.SR1 == nil || c.SmartRouting.SR1.CacheTTLSeconds != 30 || u.SmartRouting.SR1.CacheTTLSeconds != 30 {
		t.Fatal("domain conversion dropped SR1")
	}
	c.SmartRouting.SR1.CacheTTLSeconds = 0
	if c.Validate(nil) == nil {
		t.Fatal("invalid SR1 TTL accepted")
	}
}
