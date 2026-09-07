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
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
)

const TierFree = ratelimit.TierFree

// Entitlements is the plan label plus caps stamped by the control plane.
// Numeric caps are required for rate-limit enforcement (no built-in catalog).
//
// RetentionDays is deliberately outside the stamped-limits trio: it is telemetry
// metadata, not a request cap, so an instance stamped before retention existed
// must keep metering normally instead of failing closed.
type Entitlements struct {
	Tier          string `json:"tier"`
	BurstPerMin   *int   `json:"burst_per_min,omitempty"`
	QuotaPerMonth *int   `json:"quota_per_month,omitempty"`
	MaxInstances  *int   `json:"max_instances,omitempty"`
	RetentionDays *int   `json:"retention_days,omitempty"`
}

func DefaultEntitlements() Entitlements {
	return Entitlements{Tier: TierFree}
}

// HasStampedLimits reports whether all three numeric caps were stamped together.
func (e Entitlements) HasStampedLimits() bool {
	return e.BurstPerMin != nil && e.QuotaPerMonth != nil && e.MaxInstances != nil
}

// UnlimitedRetentionWindow is what an unlimited plan (retention_days == 0, the
// same sentinel the other caps use) resolves to.
//
// Unlimited cannot travel further as 0: downstream this becomes a per-trace expiry
// timestamp, and a TTL needs a real date to compare against, so the wire's
// sentinel has to become a concrete window somewhere. It stops here rather than in
// the sink, so every exporter agrees on it.
//
// Deliberately large but bounded: ClickHouse DateTime is seconds in a uint32 and
// tops out in 2106, so a far-future sentinel would saturate. A decade is unlimited
// in every sense that matters — only on-premise plans are uncapped, and they run
// their own storage.
const UnlimitedRetentionWindow = 3650 * 24 * time.Hour

// ResolveRetention returns the stamped trace retention window.
//
// Three cases, and the difference matters: never stamped reports false so no expiry
// is emitted and the sink applies its own fallback; 0 means unlimited, matching the
// other caps; anything positive is that window.
func (e Entitlements) ResolveRetention() (time.Duration, bool) {
	if e.RetentionDays == nil || *e.RetentionDays < 0 {
		return 0, false
	}
	if *e.RetentionDays == 0 {
		return UnlimitedRetentionWindow, true
	}
	return time.Duration(*e.RetentionDays) * 24 * time.Hour, true
}

// ResolveLimits returns stamped caps only. Unstamped instances have no commercial plan metering.
func (e Entitlements) ResolveLimits() (ratelimit.Limits, bool) {
	if !e.HasStampedLimits() {
		return ratelimit.Limits{}, false
	}
	return ratelimit.Limits{
		BurstPerMin:   *e.BurstPerMin,
		QuotaPerMonth: *e.QuotaPerMonth,
		MaxInstances:  *e.MaxInstances,
	}, true
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

	if e.RetentionDays != nil && *e.RetentionDays < 0 {
		return Entitlements{}, fmt.Errorf("gateway: entitlements.retention_days must be >= 0 (0 means unlimited): %w", commonerrors.ErrValidation)
	}

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
