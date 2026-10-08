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
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestHydrateConsumerRoutingReferencesDoesNotMigrate(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	raw := []byte(fmt.Sprintf(`{"enabled":true,"algorithm":"smart-routing","members":[{"registry_id":%q,"models":["low"]},{"registry_id":%q,"model":"high"}],"smart_routing":{"tiers":[{"registry_id":%q,"min_score":0.1},{"registry_id":%q,"model":"high","min_score":0.8}]}}`, id, id, id, id))
	policies, err := json.Marshal(domain.ModelPolicies{id: {Allowed: []string{"low", "high"}, Default: "low"}})
	if err != nil {
		t.Fatal(err)
	}
	var c domain.Consumer
	if err := hydrateConsumerRoutingReferences(&c, nil, policies, raw); err != nil {
		t.Fatal(err)
	}
	cfg := c.LBConfig
	if cfg.SmartRouting.SR1 != nil || cfg.SmartRouting.Tiers[0].MinScore != .1 || cfg.SmartRouting.Tiers[0].Model != "" || cfg.Members[0].Model != "" {
		t.Fatal("repository read silently canonicalized stored data")
	}
}
