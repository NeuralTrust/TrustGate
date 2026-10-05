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
	"sort"
)

// SR1Config enables the frozen paper policy with one warm escape per cache lifetime.
type SR1Config struct {
	CacheTTLSeconds int `json:"cache_ttl_seconds"`
}

func (c *SmartRoutingConfig) validateSR1() error {
	if c.SR1 == nil {
		return nil
	}
	if c.SR1.CacheTTLSeconds < 1 || c.SR1.CacheTTLSeconds > 86400 {
		return fmt.Errorf("%w: SR-1 cache_ttl_seconds must be in [1,86400]", ErrInvalidSmartRouting)
	}
	if len(c.Tiers) != 2 && len(c.Tiers) != 3 {
		return fmt.Errorf("%w: SR-1 requires two or three rungs", ErrInvalidSmartRouting)
	}
	tiers := append([]SmartRoutingTier(nil), c.Tiers...)
	sort.Slice(tiers, func(i, j int) bool { return tiers[i].MinScore < tiers[j].MinScore })
	cuts := []float64{0, 0.45}
	if len(tiers) == 3 {
		cuts = []float64{0, 0.187, 0.45}
	}
	routes := make(map[string]struct{})
	for i, tier := range tiers {
		if tier.MinScore != cuts[i] {
			return fmt.Errorf("%w: SR-1 rung %d must have min_score %g", ErrInvalidSmartRouting, i, cuts[i])
		}
		if tier.RouteModel() == "" {
			return fmt.Errorf("%w: SR-1 rungs must pin a model", ErrInvalidSmartRouting)
		}
		key := tier.RegistryID.String() + "/" + tier.RouteModel()
		if _, exists := routes[key]; exists {
			return fmt.Errorf("%w: SR-1 rungs must name distinct routes", ErrInvalidSmartRouting)
		}
		routes[key] = struct{}{}
	}
	return nil
}
