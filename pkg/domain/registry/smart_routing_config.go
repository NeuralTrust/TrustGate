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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// SmartRoutingTier binds a complexity-score threshold to a target registry. A
// tier is selected when the score is at least MinScore. Model is an optional
// override applied when the tier wins; when empty, the registry's model policy
// default is used. Multiple tiers may share a RegistryID with different models.
type SmartRoutingTier struct {
	MinScore   float64        `json:"min_score"`
	RegistryID ids.RegistryID `json:"registry_id"`
	Model      string         `json:"model,omitempty"`
}

// SmartRoutingConfig maps complexity scores in [0,1] to registries. The tier
// with the greatest MinScore that does not exceed the score wins.
type SmartRoutingConfig struct {
	Tiers []SmartRoutingTier `json:"tiers"`
}

func (c *SmartRoutingConfig) Validate() error {
	if c == nil || len(c.Tiers) == 0 {
		return fmt.Errorf("%w: at least one tier is required", ErrInvalidSmartRouting)
	}
	seen := make(map[float64]struct{}, len(c.Tiers))
	for i, tier := range c.Tiers {
		if tier.MinScore < 0 || tier.MinScore > 1 {
			return fmt.Errorf("%w: tiers[%d].min_score must be in [0,1]", ErrInvalidSmartRouting, i)
		}
		if _, dup := seen[tier.MinScore]; dup {
			return fmt.Errorf("%w: tiers[%d].min_score %g is duplicated", ErrInvalidSmartRouting, i, tier.MinScore)
		}
		seen[tier.MinScore] = struct{}{}
		if tier.RegistryID.IsNil() {
			return fmt.Errorf("%w: tiers[%d].registry_id is required", ErrInvalidSmartRouting, i)
		}
	}
	return nil
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

// RegistryForScore returns the registry mapped to the given complexity score:
// the tier with the greatest MinScore that is not above the score. It reports
// false when no tier applies (e.g. the score is below every threshold).
func (c *SmartRoutingConfig) RegistryForScore(score float64) (ids.RegistryID, bool) {
	tier, ok := c.TierForScore(score)
	if !ok {
		return ids.RegistryID{}, false
	}
	return tier.RegistryID, true
}

// ModelForScore returns the optional model override for the winning tier.
func (c *SmartRoutingConfig) ModelForScore(score float64) (string, bool) {
	tier, ok := c.TierForScore(score)
	if !ok {
		return "", false
	}
	model := strings.TrimSpace(tier.Model)
	if model == "" {
		return "", false
	}
	return model, true
}
