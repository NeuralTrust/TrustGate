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
	"slices"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
)

type LBPoolMember struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Models     []string       `json:"models,omitempty"`
	Model      string         `json:"model,omitempty"`
	Weight     *int           `json:"weight,omitempty"`
}

func (m LBPoolMember) RouteModel() string {
	return strings.TrimSpace(m.Model)
}

func (m LBPoolMember) RouteWeight(fallback int) int {
	if m.Weight == nil || *m.Weight <= 0 {
		return fallback
	}
	return *m.Weight
}

type LBConfig struct {
	Enabled         bool                         `json:"enabled"`
	Algorithm       string                       `json:"algorithm,omitempty"`
	PoolAlias       string                       `json:"pool_alias,omitempty"`
	Members         []LBPoolMember               `json:"members,omitempty"`
	EmbeddingConfig *registry.EmbeddingConfig    `json:"embedding_config,omitempty"`
	SmartRouting    *registry.SmartRoutingConfig `json:"smart_routing,omitempty"`
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
	if err := l.validateRouteIdentity(); err != nil {
		return err
	}
	switch l.Algorithm {
	case algorithm.Semantic:
		if l.SmartRouting != nil {
			return fmt.Errorf("%w: smart_routing is only valid for the smart-routing algorithm", ErrInvalidLBConfig)
		}
		if l.EmbeddingConfig == nil {
			return fmt.Errorf("%w: embedding_config required for semantic algorithm", ErrInvalidLBConfig)
		}
		if err := l.EmbeddingConfig.Validate(); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidLBConfig, err.Error())
		}
		return nil
	case algorithm.SmartRouting:
		if l.EmbeddingConfig != nil {
			return fmt.Errorf("%w: embedding_config is only valid for the semantic algorithm", ErrInvalidLBConfig)
		}
		if l.SmartRouting == nil {
			return fmt.Errorf("%w: smart_routing required for smart-routing algorithm", ErrInvalidLBConfig)
		}
		if err := l.SmartRouting.Validate(); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidLBConfig, err.Error())
		}
		return l.validateSmartRoutingTiers()
	default:
		if l.EmbeddingConfig != nil {
			return fmt.Errorf("%w: embedding_config is only valid for the semantic algorithm", ErrInvalidLBConfig)
		}
		if l.SmartRouting != nil {
			return fmt.Errorf("%w: smart_routing is only valid for the smart-routing algorithm", ErrInvalidLBConfig)
		}
		return nil
	}
}

func (l *LBConfig) validateRouteIdentity() error {
	type routeKey struct {
		registryID ids.RegistryID
		model      string
	}
	perRegistry := make(map[ids.RegistryID]int, len(l.Members))
	for _, member := range l.Members {
		perRegistry[member.RegistryID]++
	}
	seen := make(map[routeKey]struct{}, len(l.Members))
	for i, member := range l.Members {
		model := member.RouteModel()
		if model == "" && perRegistry[member.RegistryID] > 1 {
			return fmt.Errorf(
				"%w: members[%d] repeats registry %s without a model; every member sharing a registry must declare one",
				ErrInvalidLBConfig, i, member.RegistryID)
		}
		key := routeKey{registryID: member.RegistryID, model: model}
		if _, dup := seen[key]; dup {
			return fmt.Errorf(
				"%w: members[%d] duplicates route %s/%s", ErrInvalidLBConfig, i, member.RegistryID, model)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (l *LBConfig) validateSmartRoutingTiers() error {
	routes := make(map[ids.RegistryID][]string, len(l.Members))
	for _, member := range l.Members {
		routes[member.RegistryID] = append(routes[member.RegistryID], member.RouteModel())
	}
	for i, tier := range l.SmartRouting.Tiers {
		models, ok := routes[tier.RegistryID]
		if !ok {
			return fmt.Errorf(
				"%w: smart_routing.tiers[%d].registry_id %s is not a pool member",
				ErrInvalidLBConfig, i, tier.RegistryID)
		}
		model := tier.RouteModel()
		if model == "" {
			if len(models) > 1 {
				return fmt.Errorf(
					"%w: smart_routing.tiers[%d] targets registry %s, which has %d routes; declare a model",
					ErrInvalidLBConfig, i, tier.RegistryID, len(models))
			}
			continue
		}
		if !slices.Contains(models, model) {
			return fmt.Errorf(
				"%w: smart_routing.tiers[%d].model %q is not a route of registry %s",
				ErrInvalidLBConfig, i, model, tier.RegistryID)
		}
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
	if member.Weight != nil && (*member.Weight < DefaultRegistryWeight || *member.Weight > MaxRegistryWeight) {
		return fmt.Errorf("%w: members[%d].weight %d is out of range [%d,%d]",
			ErrInvalidLBConfig, index, *member.Weight, DefaultRegistryWeight, MaxRegistryWeight)
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
	return validateLBPoolMemberModel(index, member, seen, allowed)
}

// An open allow-list permits every model, so a pinned model is only checked against a non-empty one.
func validateLBPoolMemberModel(
	index int,
	member LBPoolMember,
	memberModels map[string]struct{},
	allowed map[string]struct{},
) error {
	model := member.RouteModel()
	if model == "" {
		if member.Model != "" {
			return fmt.Errorf("%w: members[%d].model is blank", ErrInvalidLBConfig, index)
		}
		return nil
	}
	if len(memberModels) > 0 {
		if _, ok := memberModels[model]; !ok {
			return fmt.Errorf("%w: members[%d].model %q is not listed in members[%d].models",
				ErrInvalidLBConfig, index, model, index)
		}
	}
	if len(allowed) > 0 {
		if _, ok := allowed[model]; !ok {
			return fmt.Errorf("%w: members[%d].model %q is not allowed by model_policies",
				ErrInvalidLBConfig, index, model)
		}
	}
	return nil
}
