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
	"fmt"
	"math"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
)

// SmartRoutingTier binds a complexity-score threshold to a target route. A tier
// is selected when the score is at least MinScore.
type SmartRoutingTier struct {
	MinScore   float64        `json:"min_score"`
	RegistryID ids.RegistryID `json:"registry_id"`
	Model      string         `json:"model,omitempty"`
}

func (t SmartRoutingTier) RouteModel() string {
	return strings.TrimSpace(t.Model)
}

// SmartRoutingConfig maps complexity scores in [0,1] to registries. The tier
// with the greatest MinScore that does not exceed the score wins.
type SmartRoutingConfig struct {
	Tiers            []SmartRoutingTier `json:"tiers"`
	SR1              *SR1Config         `json:"sr1,omitempty"`
	LegacyThresholds bool               `json:"legacy_thresholds,omitempty"`
}

func (c *SmartRoutingConfig) Validate() error {
	if c == nil || len(c.Tiers) < 2 || (!c.LegacyThresholds && len(c.Tiers) > 3) {
		return fmt.Errorf("%w: smart routing requires two or three rungs", ErrInvalidSmartRouting)
	}
	if c.SR1 == nil {
		return fmt.Errorf("%w: session commitment configuration is required", ErrInvalidSmartRouting)
	}
	if c.SR1.CacheTTLSeconds < 1 || c.SR1.CacheTTLSeconds > 86400 {
		return fmt.Errorf("%w: cache_ttl_seconds must be in [1,86400]", ErrInvalidSmartRouting)
	}
	cuts := map[float64]bool{0: false, .45: false}
	if len(c.Tiers) == 3 {
		cuts[.187] = false
	}
	routes := make(map[string]struct{}, len(c.Tiers))
	scores := make(map[float64]struct{}, len(c.Tiers))
	for i, tier := range c.Tiers {
		seen, valid := cuts[tier.MinScore]
		_, duplicate := scores[tier.MinScore]
		if math.IsNaN(tier.MinScore) || math.IsInf(tier.MinScore, 0) || tier.MinScore < 0 || tier.MinScore > 1 || duplicate {
			return fmt.Errorf("%w: tiers[%d].min_score must be distinct and in [0,1]", ErrInvalidSmartRouting, i)
		}
		if !c.LegacyThresholds && (!valid || seen) {
			return fmt.Errorf("%w: tiers[%d].min_score must be a distinct frozen cut", ErrInvalidSmartRouting, i)
		}
		scores[tier.MinScore] = struct{}{}
		cuts[tier.MinScore] = true
		if tier.RegistryID.IsNil() {
			return fmt.Errorf("%w: tiers[%d].registry_id is required", ErrInvalidSmartRouting, i)
		}
		model := tier.RouteModel()
		if model == "" {
			return fmt.Errorf("%w: tiers[%d].model is required", ErrInvalidSmartRouting, i)
		}
		if err := modelmatch.RequireConcrete(fmt.Sprintf("tiers[%d].model", i), model); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSmartRouting, err)
		}
		key := tier.RegistryID.String() + "/" + model
		if _, exists := routes[key]; exists {
			return fmt.Errorf("%w: rungs must name distinct routes", ErrInvalidSmartRouting)
		}
		routes[key] = struct{}{}
	}
	return nil
}

func (c *SmartRoutingConfig) HighestTier() (SmartRoutingTier, bool) {
	if c == nil || len(c.Tiers) == 0 {
		return SmartRoutingTier{}, false
	}
	best := c.Tiers[0]
	for _, tier := range c.Tiers[1:] {
		if tier.MinScore > best.MinScore {
			best = tier
		}
	}
	return best, true
}

// TierForScore returns the tier mapped to the given complexity score: the one
// with the greatest MinScore that is not above the score. It reports false when
// no tier applies (e.g. the score is below every threshold).
func (c *SmartRoutingConfig) TierForScore(score float64) (SmartRoutingTier, bool) {
	var (
		best     SmartRoutingTier
		bestMin  float64
		selected bool
	)
	for _, tier := range c.Tiers {
		if tier.MinScore > score {
			continue
		}
		if !selected || tier.MinScore > bestMin {
			best = tier
			bestMin = tier.MinScore
			selected = true
		}
	}
	return best, selected
}
