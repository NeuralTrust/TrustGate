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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func validateLegacyRoutingWrite(next, previous *consumer.LBConfig) error {
	if next == nil || next.SmartRouting == nil {
		return nil
	}
	if previous != nil && previous.SmartRouting != nil && previous.SmartRouting.LegacyThresholds {
		if !sameLegacyTiers(next.SmartRouting.Tiers, previous.SmartRouting.Tiers) {
			return fmt.Errorf("%w: migrated ladder routes and thresholds must be retained", consumer.ErrInvalidLBConfig)
		}
		next.SmartRouting.LegacyThresholds = true
		return nil
	}
	if next.SmartRouting.LegacyThresholds {
		return fmt.Errorf("%w: legacy thresholds may only retain a migrated ladder", consumer.ErrInvalidLBConfig)
	}
	return nil
}

func sameLegacyTiers(next, previous []registry.SmartRoutingTier) bool {
	if len(next) != len(previous) {
		return false
	}
	stored := make(map[registry.SmartRoutingTier]struct{}, len(previous))
	for _, tier := range previous {
		stored[tier] = struct{}{}
	}
	for _, tier := range next {
		if _, ok := stored[tier]; !ok {
			return false
		}
		delete(stored, tier)
	}
	return len(stored) == 0
}
