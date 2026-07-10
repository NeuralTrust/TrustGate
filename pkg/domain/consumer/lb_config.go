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
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

type LBPoolMember struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Models     []string       `json:"models,omitempty"`
}

type LBConfig struct {
	Enabled         bool                      `json:"enabled"`
	Algorithm       string                    `json:"algorithm,omitempty"`
	PoolAlias       string                    `json:"pool_alias,omitempty"`
	Members         []LBPoolMember            `json:"members,omitempty"`
	EmbeddingConfig *registry.EmbeddingConfig `json:"embedding_config,omitempty"`
}

func (l LBConfig) Value() (driver.Value, error) {
	return json.Marshal(l)
}

func (l *LBConfig) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, l)
}

func (l *LBConfig) Validate(inline ModelPolicies) error {
	if l == nil || !l.Enabled {
		return nil
	}
	if l.Algorithm == "" {
		l.Algorithm = algorithm.RoundRobin
	}
	if !algorithm.IsValid(l.Algorithm) {
		return fmt.Errorf("%w: invalid algorithm %q", ErrInvalidLBConfig, l.Algorithm)
	}
	if len(l.Members) == 0 {
		return fmt.Errorf("%w: members are required when enabled", ErrInvalidLBConfig)
	}
	for i, member := range l.Members {
		if err := validateLBPoolMember(i, member, inline); err != nil {
			return err
		}
	}
	if l.Algorithm == algorithm.Semantic {
		if l.EmbeddingConfig == nil {
			return fmt.Errorf("%w: embedding_config required for semantic algorithm", ErrInvalidLBConfig)
		}
		if err := l.EmbeddingConfig.Validate(); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidLBConfig, err.Error())
		}
		return nil
	}
	if l.EmbeddingConfig != nil {
		return fmt.Errorf("%w: embedding_config is only valid for the semantic algorithm", ErrInvalidLBConfig)
	}
	return nil
}

func validateLBPoolMember(index int, member LBPoolMember, inline ModelPolicies) error {
	if member.RegistryID.IsNil() {
		return fmt.Errorf("%w: members[%d].registry_id is required", ErrInvalidLBConfig, index)
	}
	policy, ok := inline.For(member.RegistryID)
	if !ok {
		return fmt.Errorf("%w: members[%d].registry_id %s is not in model_policies", ErrInvalidLBConfig, index, member.RegistryID)
	}
	allowed := make(map[string]struct{}, len(policy.Allowed))
	for _, model := range policy.Allowed {
		allowed[model] = struct{}{}
	}
	seen := make(map[string]struct{}, len(member.Models))
	for _, model := range member.Models {
		if model == "" {
			return fmt.Errorf("%w: members[%d].models contains empty model", ErrInvalidLBConfig, index)
		}
		if _, dup := seen[model]; dup {
			return fmt.Errorf("%w: members[%d].models duplicate %q", ErrInvalidLBConfig, index, model)
		}
		seen[model] = struct{}{}
		if _, ok := allowed[model]; !ok {
			return fmt.Errorf("%w: members[%d].model %q is not allowed by model_policies", ErrInvalidLBConfig, index, model)
		}
	}
	return nil
}
