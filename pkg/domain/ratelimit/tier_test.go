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

import "testing"

func TestLimitsFor(t *testing.T) {
	tests := []struct {
		tier             string
		wantOK           bool
		wantBurst        int
		wantQuota        int
		wantHasQuota     bool
		wantMaxInstances int
		wantHasCap       bool
	}{
		{tier: "free", wantOK: true, wantBurst: 60, wantQuota: 10_000, wantHasQuota: true, wantMaxInstances: 5, wantHasCap: true},
		{tier: " Free ", wantOK: true, wantBurst: 60, wantQuota: 10_000, wantHasQuota: true, wantMaxInstances: 5, wantHasCap: true},
		{tier: "standard", wantOK: true, wantBurst: 300, wantQuota: 100_000, wantHasQuota: true, wantMaxInstances: 5, wantHasCap: true},
		{tier: "STANDARD", wantOK: true, wantBurst: 300, wantQuota: 100_000, wantHasQuota: true, wantMaxInstances: 5, wantHasCap: true},
		{tier: "enterprise", wantOK: true, wantBurst: 1_000, wantQuota: 0, wantHasQuota: false, wantMaxInstances: 5, wantHasCap: true},
		{tier: "gold", wantOK: false},
		{tier: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			limits, ok := LimitsFor(tt.tier)
			if ok != tt.wantOK {
				t.Fatalf("LimitsFor(%q) ok = %v, want %v", tt.tier, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if limits.BurstPerMin != tt.wantBurst {
				t.Fatalf("BurstPerMin = %d, want %d", limits.BurstPerMin, tt.wantBurst)
			}
			if limits.QuotaPerMonth != tt.wantQuota {
				t.Fatalf("QuotaPerMonth = %d, want %d", limits.QuotaPerMonth, tt.wantQuota)
			}
			if limits.HasMonthlyQuota() != tt.wantHasQuota {
				t.Fatalf("HasMonthlyQuota() = %v, want %v", limits.HasMonthlyQuota(), tt.wantHasQuota)
			}
			if limits.MaxInstances != tt.wantMaxInstances {
				t.Fatalf("MaxInstances = %d, want %d", limits.MaxInstances, tt.wantMaxInstances)
			}
			if limits.HasInstanceCap() != tt.wantHasCap {
				t.Fatalf("HasInstanceCap() = %v, want %v", limits.HasInstanceCap(), tt.wantHasCap)
			}
		})
	}
}
