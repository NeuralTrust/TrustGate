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

package ratelimit

import "strings"

const (
	TierFree       = "free"
	TierStandard   = "standard"
	TierEnterprise = "enterprise"
)

// Limits are plan caps stamped by the control plane onto each instance.
// QuotaPerMonth == 0 means unlimited, MaxInstances == 0 means unlimited.
type Limits struct {
	BurstPerMin   int
	QuotaPerMonth int
	MaxInstances  int
}

var knownTiers = map[string]struct{}{
	TierFree:       {},
	TierStandard:   {},
	TierEnterprise: {},
}

// IsKnownTier reports whether name is a recognized plan label (no numeric caps here).
func IsKnownTier(tier string) bool {
	_, ok := knownTiers[strings.ToLower(strings.TrimSpace(tier))]
	return ok
}

func (l Limits) HasMonthlyQuota() bool {
	return l.QuotaPerMonth > 0
}

func (l Limits) HasInstanceCap() bool {
	return l.MaxInstances > 0
}
