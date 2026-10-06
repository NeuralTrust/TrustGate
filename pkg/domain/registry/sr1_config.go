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

package registry

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
)

// SR1Config configures the sole cold-point policy and its optional warm escape.
type SR1Config struct {
	CacheTTLSeconds    int   `json:"cache_ttl_seconds"`
	EscapeHatchEnabled *bool `json:"escape_hatch_enabled,omitempty"`
}

// UnmarshalJSON distinguishes a historical omitted flag from an invalid null flag.
func (c *SR1Config) UnmarshalJSON(raw []byte) error {
	type wire SR1Config
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for name, value := range fields {
		if strings.EqualFold(name, "escape_hatch_enabled") && strings.TrimSpace(string(value)) == "null" {
			return fmt.Errorf("%w: escape_hatch_enabled must be a boolean", ErrInvalidSmartRouting)
		}
	}
	*c = SR1Config(decoded)
	return nil
}

// EscapeEnabled preserves the enabled hatch on historical explicit SR1 envelopes.
func (c *SR1Config) EscapeEnabled() bool {
	return c != nil && (c.EscapeHatchEnabled == nil || *c.EscapeHatchEnabled)
}

// Normalize resolves historical configuration into the sole fixed-cut policy.
func (c *SmartRoutingConfig) Normalize() (*SmartRoutingConfig, error) {
	if c == nil || (len(c.Tiers) != 2 && len(c.Tiers) != 3) {
		return nil, fmt.Errorf("%w: smart routing requires two or three rungs", ErrInvalidSmartRouting)
	}
	tiers := append([]SmartRoutingTier(nil), c.Tiers...)
	sort.SliceStable(tiers, func(i, j int) bool { return tiers[i].MinScore < tiers[j].MinScore })
	seen := make(map[float64]struct{}, len(tiers))
	for i, tier := range tiers {
		if math.IsNaN(tier.MinScore) || math.IsInf(tier.MinScore, 0) || tier.MinScore < 0 || tier.MinScore > 1 {
			return nil, fmt.Errorf("%w: tiers[%d].min_score must be in [0,1]", ErrInvalidSmartRouting, i)
		}
		if _, duplicate := seen[tier.MinScore]; duplicate {
			return nil, fmt.Errorf("%w: tiers[%d].min_score is duplicated", ErrInvalidSmartRouting, i)
		}
		seen[tier.MinScore] = struct{}{}
		if tier.RegistryID.IsNil() {
			return nil, fmt.Errorf("%w: tiers[%d].registry_id is required", ErrInvalidSmartRouting, i)
		}
	}
	escape := c.SR1.EscapeEnabled()
	ttl := 300
	if c.SR1 != nil {
		ttl = c.SR1.CacheTTLSeconds
	}
	if ttl < 1 || ttl > 86400 {
		return nil, fmt.Errorf("%w: cache_ttl_seconds must be in [1,86400]", ErrInvalidSmartRouting)
	}
	cuts := []float64{0, 0.45}
	if len(tiers) == 3 {
		cuts = []float64{0, 0.187, 0.45}
	}
	routes := make(map[string]struct{})
	for i, tier := range tiers {
		if c.SR1 == nil {
			tiers[i].MinScore = cuts[i]
		} else if tier.MinScore != cuts[i] {
			return nil, fmt.Errorf("%w: rung %d must have min_score %g", ErrInvalidSmartRouting, i, cuts[i])
		}
		if tier.RouteModel() == "" {
			return nil, fmt.Errorf("%w: rungs must pin a model", ErrInvalidSmartRouting)
		}
		if err := modelmatch.RequireConcrete(fmt.Sprintf("tiers[%d].model", i), tier.RouteModel()); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSmartRouting, err)
		}
		key := tier.RegistryID.String() + "/" + tier.RouteModel()
		if _, exists := routes[key]; exists {
			return nil, fmt.Errorf("%w: rungs must name distinct routes", ErrInvalidSmartRouting)
		}
		routes[key] = struct{}{}
	}
	return &SmartRoutingConfig{Tiers: tiers, SR1: &SR1Config{CacheTTLSeconds: ttl, EscapeHatchEnabled: &escape}}, nil
}

// MarshalJSON emits explicit hatch settings for database writes and config sync.
func (c SmartRoutingConfig) MarshalJSON() ([]byte, error) {
	normalized, err := c.Normalize()
	type wire SmartRoutingConfig
	if err != nil {
		return json.Marshal(wire(c))
	}
	return json.Marshal((*wire)(normalized))
}

// UnmarshalJSON migrates supported historical ladders without hiding invalid routes.
func (c *SmartRoutingConfig) UnmarshalJSON(raw []byte) error {
	type wire SmartRoutingConfig
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	*c = SmartRoutingConfig(decoded)
	if normalized, err := c.Normalize(); err == nil {
		*c = *normalized
	}
	return nil
}
