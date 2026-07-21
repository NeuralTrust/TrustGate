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

// Entitlements is the plan label plus optional caps stamped by the control plane.
// Stamped caps win; if absent, ResolveLimits falls back to LimitsFor(tier) for legacy rows.
type Entitlements struct {
	Tier          string `json:"tier"`
	BurstPerMin   *int   `json:"burst_per_min,omitempty"`
	QuotaPerMonth *int   `json:"quota_per_month,omitempty"`
	MaxInstances  *int   `json:"max_instances,omitempty"`
}

func DefaultEntitlements() Entitlements {
	return Entitlements{Tier: TierFree}
}

// HasStampedLimits reports whether all three numeric caps were stamped together.
func (e Entitlements) HasStampedLimits() bool {
	return e.BurstPerMin != nil && e.QuotaPerMonth != nil && e.MaxInstances != nil
}

// ResolveLimits prefers stamped caps; otherwise LimitsFor(tier) (empty → free) for unstamped instances.
func (e Entitlements) ResolveLimits() (ratelimit.Limits, bool) {
	if e.HasStampedLimits() {
		return ratelimit.Limits{
			BurstPerMin:   *e.BurstPerMin,
			QuotaPerMonth: *e.QuotaPerMonth,
			MaxInstances:  *e.MaxInstances,
		}, true
	}
	tier := strings.ToLower(strings.TrimSpace(e.Tier))
	if tier == "" {
		tier = TierFree
	}
	return ratelimit.LimitsFor(tier)
}

// ValidateTier normalizes tier and rejects unknown plan labels; empty means free.
func ValidateTier(tier string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(tier))
	if normalized == "" {
		return TierFree, nil
	}
	if !ratelimit.IsKnownTier(normalized) {
		return "", fmt.Errorf("gateway: entitlements.tier must be one of free, standard, enterprise: %w", commonerrors.ErrValidation)
	}
	return normalized, nil
}

// NormalizeEntitlements validates tier and requires stamped caps when any limit field is present;
// API payloads that include entitlements should send all three caps (control-plane stamp).
func NormalizeEntitlements(e Entitlements) (Entitlements, error) {
	tier, err := ValidateTier(e.Tier)
	if err != nil {
		return Entitlements{}, err
	}
	e.Tier = tier

	anyLimit := e.BurstPerMin != nil || e.QuotaPerMonth != nil || e.MaxInstances != nil
	if !anyLimit {
		return e, nil
	}
	if !e.HasStampedLimits() {
		return Entitlements{}, fmt.Errorf("gateway: entitlements stamped limits must set burst_per_min, quota_per_month, and max_instances together: %w", commonerrors.ErrValidation)
	}
	if *e.BurstPerMin <= 0 {
		return Entitlements{}, fmt.Errorf("gateway: entitlements.burst_per_min must be > 0: %w", commonerrors.ErrValidation)
	}
	if *e.QuotaPerMonth < 0 {
		return Entitlements{}, fmt.Errorf("gateway: entitlements.quota_per_month must be >= 0: %w", commonerrors.ErrValidation)
	}
	if *e.MaxInstances < 0 {
		return Entitlements{}, fmt.Errorf("gateway: entitlements.max_instances must be >= 0: %w", commonerrors.ErrValidation)
	}
	return e, nil
}

// RequireStampedEntitlements is used when the control plane sends an entitlements object (upgrade/downgrade scripts).
func RequireStampedEntitlements(e Entitlements) (Entitlements, error) {
	normalized, err := NormalizeEntitlements(e)
	if err != nil {
		return Entitlements{}, err
	}
	if !normalized.HasStampedLimits() {
		return Entitlements{}, fmt.Errorf("gateway: entitlements must include burst_per_min, quota_per_month, and max_instances: %w", commonerrors.ErrValidation)
	}
	return normalized, nil
}
