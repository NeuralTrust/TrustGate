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

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

func canonicalSingleRoutingJSON(raw []byte, config consumer.LBConfig, policies consumer.ModelPolicies, known map[ids.RegistryID]struct{}) ([]byte, error) {
	tier := config.SmartRouting.Tiers[0]
	if _, ok := known[tier.RegistryID]; !ok {
		return nil, fmt.Errorf("single tier registry is not a registry of the consumer")
	}
	selected := -1
	for i, member := range config.Members {
		if member.RegistryID == tier.RegistryID && member.RouteModel() == tier.RouteModel() {
			if selected >= 0 {
				return nil, fmt.Errorf("single tier has duplicate member routes")
			}
			selected = i
		}
	}
	if selected < 0 {
		return nil, fmt.Errorf("single tier does not match a declared member route")
	}
	config.Algorithm = algorithm.RoundRobin
	config.SmartRouting = nil
	config.Members = []consumer.LBPoolMember{config.Members[selected]}
	validation := config
	validation.Enabled = true
	if err := policies.Validate(known); err != nil {
		return nil, err
	}
	if err := validation.Validate(policies); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	var members []map[string]json.RawMessage
	if err := json.Unmarshal(fields["members"], &members); err != nil {
		return nil, err
	}
	model, err := json.Marshal(config.Members[0].Model)
	if err != nil {
		return nil, err
	}
	members[selected]["model"] = model
	fields["members"], err = json.Marshal(members[selected : selected+1])
	if err != nil {
		return nil, err
	}
	fields["algorithm"], err = json.Marshal(algorithm.RoundRobin)
	if err != nil {
		return nil, err
	}
	delete(fields, "smart_routing")
	return json.Marshal(fields)
}
