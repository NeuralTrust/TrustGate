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
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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
	for backendID, policy := range m {
		if backendID.IsNil() {
			return fmt.Errorf("%w: nil registry_id", ErrInvalidModelPolicy)
		}
		if _, ok := validRegistryIDs[backendID]; !ok {
			return fmt.Errorf("%w: backend %s is not in pool or fallback chain", ErrInvalidModelPolicy, backendID)
		}
		if err := policy.validate(backendID); err != nil {
			return err
		}
	}
	return nil
}

func (p ModelPolicy) validate(backendID ids.RegistryID) error {
	if p.Allowed != nil && len(p.Allowed) == 0 {
		return fmt.Errorf("%w: empty allow-list for backend %s (omit allowed to permit all models)", ErrInvalidModelPolicy, backendID)
	}
	seen := make(map[string]struct{}, len(p.Allowed))
	for _, model := range p.Allowed {
		if model == "" {
			return fmt.Errorf("%w: empty model in allow-list for backend %s", ErrInvalidModelPolicy, backendID)
		}
		if _, dup := seen[model]; dup {
			return fmt.Errorf("%w: duplicate model %q for backend %s", ErrInvalidModelPolicy, model, backendID)
		}
		seen[model] = struct{}{}
	}
	if p.Default != "" && len(p.Allowed) > 0 {
		if _, ok := seen[p.Default]; !ok {
			return fmt.Errorf("%w: default model %q not in allow-list for backend %s", ErrInvalidModelPolicy, p.Default, backendID)
		}
	}
	return nil
}

func (m ModelPolicies) For(backendID ids.RegistryID) (ModelPolicy, bool) {
	if m == nil {
		return ModelPolicy{}, false
	}
	p, ok := m[backendID]
	return p, ok
}
