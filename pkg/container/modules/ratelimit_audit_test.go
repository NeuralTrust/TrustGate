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
	"testing"
	"time"

	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
)

func TestRolloutAuditAppliesOnlyWhereEveryTenantIsVisible(t *testing.T) {
	t.Parallel()
	postgres := ratelimitapp.NewTenantCapsCache(nil, time.Minute, nil)
	cases := []struct {
		name  string
		cfg   config.RateLimitConfig
		caps  *ratelimitapp.TenantCapsCache
		apply bool
	}{
		{"postgres plane in the rollout month", config.RateLimitConfig{Enabled: true, RolloutAuditMonth: "2026-10"}, postgres, true},
		{"no month configured", config.RateLimitConfig{Enabled: true}, postgres, false},
		{"limiter off", config.RateLimitConfig{RolloutAuditMonth: "2026-10"}, postgres, false},
		{"snapshot plane: scoped snapshots resolve almost no legacy key", config.RateLimitConfig{Enabled: true, RolloutAuditMonth: "2026-10"}, nil, false},
	}
	for _, c := range cases {
		if got := rolloutAuditApplies(&config.Config{RateLimit: c.cfg}, c.caps); got != c.apply {
			t.Errorf("%s: applies = %v, want %v", c.name, got, c.apply)
		}
	}
}
