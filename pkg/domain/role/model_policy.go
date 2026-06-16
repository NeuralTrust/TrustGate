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

package role

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type ModelPolicy struct {
	Allowed []string `json:"allowed,omitempty"`
	Default string   `json:"default,omitempty"`
}

type ModelPolicies map[ids.RegistryID]ModelPolicy

func (m ModelPolicies) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

func (m *ModelPolicies) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, m)
}

func (m ModelPolicies) Validate(validRegistryIDs map[ids.RegistryID]struct{}) error {
	for registryID, policy := range m {
		if registryID.IsNil() {
			return fmt.Errorf("%w: nil registry_id", ErrInvalidModelPolicy)
		}
		if _, ok := validRegistryIDs[registryID]; !ok {
			return fmt.Errorf("%w: registry %s is not bound to role", ErrInvalidModelPolicy, registryID)
		}
		if err := policy.validate(registryID); err != nil {
			return err
		}
	}
	return nil
}

func (p ModelPolicy) validate(registryID ids.RegistryID) error {
	if p.Allowed != nil && len(p.Allowed) == 0 {
		return fmt.Errorf("%w: empty allow-list for registry %s (omit allowed to permit all models)", ErrInvalidModelPolicy, registryID)
	}
	seen := make(map[string]struct{}, len(p.Allowed))
	for _, model := range p.Allowed {
		if model == "" {
			return fmt.Errorf("%w: empty model in allow-list for registry %s", ErrInvalidModelPolicy, registryID)
		}
		if _, dup := seen[model]; dup {
			return fmt.Errorf("%w: duplicate model %q for registry %s", ErrInvalidModelPolicy, model, registryID)
		}
		seen[model] = struct{}{}
	}
	if p.Default != "" && len(p.Allowed) > 0 {
		if _, ok := seen[p.Default]; !ok {
			return fmt.Errorf("%w: default model %q not in allow-list for registry %s", ErrInvalidModelPolicy, p.Default, registryID)
		}
	}
	return nil
}
