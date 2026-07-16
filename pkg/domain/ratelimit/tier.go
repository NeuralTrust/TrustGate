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

// Limits are plan caps; QuotaPerMonth == 0 means unlimited, MaxInstances == 0 means unlimited.
// Create inherits the highest sibling tier so MaxInstances stays consistent under immutable entitlements.
type Limits struct {
	BurstPerMin   int
	QuotaPerMonth int
	MaxInstances  int
}

var tiers = map[string]Limits{
	TierFree:       {BurstPerMin: 60, QuotaPerMonth: 10_000, MaxInstances: 1},
	TierStandard:   {BurstPerMin: 300, QuotaPerMonth: 100_000, MaxInstances: 2},
	TierEnterprise: {BurstPerMin: 1_000, QuotaPerMonth: 0, MaxInstances: 0},
}

func LimitsFor(tier string) (Limits, bool) {
	limits, ok := tiers[strings.ToLower(strings.TrimSpace(tier))]
	return limits, ok
}

func (l Limits) HasMonthlyQuota() bool {
	return l.QuotaPerMonth > 0
}

func (l Limits) HasInstanceCap() bool {
	return l.MaxInstances > 0
}
