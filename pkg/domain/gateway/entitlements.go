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

package gateway

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
)

const TierFree = ratelimit.TierFree

type Entitlements struct {
	Tier string `json:"tier"`
}

func DefaultEntitlements() Entitlements {
	return Entitlements{Tier: TierFree}
}

// ValidateTier normalizes tier and rejects anything outside the known rate-limit tiers; empty means free.
func ValidateTier(tier string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(tier))
	if normalized == "" {
		return TierFree, nil
	}
	if _, ok := ratelimit.LimitsFor(normalized); !ok {
		return "", fmt.Errorf("gateway: entitlements.tier must be one of free, standard, enterprise: %w", commonerrors.ErrValidation)
	}
	return normalized, nil
}
