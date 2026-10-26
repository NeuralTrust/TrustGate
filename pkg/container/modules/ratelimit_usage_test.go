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

package modules

import (
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

func TestMeterQuotaYieldsOnlyWhereTheUsageGuardRefuses(t *testing.T) {
	received := appusage.NewEnforcement()
	received.ApplySnapshot(domain.Snapshot{AsOfVersion: 1})
	cacheOnly := appusage.NewEnforcement()
	cacheOnly.ApplySnapshot(domain.Snapshot{})
	tests := []struct {
		name  string
		guard *middleware.UsageGuardMiddleware
		want  bool
	}{
		{name: "no usage guard on the plane", guard: nil, want: false},
		{name: "a plane that cannot enforce usage", guard: middleware.NewUsageGuardMiddleware(nil, nil), want: false},
		{name: "usage enforcement turned off", guard: middleware.NewUsageGuardMiddleware(received, func() bool { return false }), want: false},
		{name: "enforced with a list that never came from Usage System", guard: middleware.NewUsageGuardMiddleware(cacheOnly, func() bool { return true }), want: false},
		{name: "enforced before the first usage list", guard: middleware.NewUsageGuardMiddleware(appusage.NewEnforcement(), func() bool { return true }), want: false},
		{name: "enforced with a usage list", guard: middleware.NewUsageGuardMiddleware(received, func() bool { return true }), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := rateLimitDeps{Cfg: &config.Config{}, Usage: tt.guard}.meterOptions()
			if got := opts.UsageRefusing(); got != tt.want {
				t.Fatalf("meter skips the quota = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMeterQuotaFollowsTheUsageFlagOnEveryCall(t *testing.T) {
	received := appusage.NewEnforcement()
	received.ApplySnapshot(domain.Snapshot{AsOfVersion: 1})
	var on atomic.Bool
	opts := rateLimitDeps{Cfg: &config.Config{}, Usage: middleware.NewUsageGuardMiddleware(received, on.Load)}.meterOptions()

	if opts.UsageRefusing() {
		t.Fatal("quota skipped while usage enforcement is off")
	}
	on.Store(true)
	if !opts.UsageRefusing() {
		t.Fatal("quota still applied after usage enforcement turned on")
	}
}
