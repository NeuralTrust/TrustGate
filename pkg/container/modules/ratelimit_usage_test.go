// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modules

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

type fixedChecker struct{}

func (fixedChecker) Exhausted(string) (domain.Reason, bool) { return domain.ReasonNone, false }

func TestMeterQuotaYieldsExactlyWhereTheUsageGuardEnforces(t *testing.T) {
	tests := []struct {
		name  string
		guard *middleware.UsageGuardMiddleware
		want  bool
	}{
		{name: "no usage guard on the plane", guard: nil, want: false},
		{name: "a plane that cannot enforce usage", guard: middleware.NewUsageGuardMiddleware(nil, nil), want: false},
		{name: "usage enforcement turned off", guard: middleware.NewUsageGuardMiddleware(fixedChecker{}, func() bool { return false }), want: false},
		{name: "usage enforced", guard: middleware.NewUsageGuardMiddleware(fixedChecker{}, func() bool { return true }), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := rateLimitDeps{Cfg: &config.Config{}, Usage: tt.guard}.meterOptions()
			if got := opts.UsageEnforcing(); got != tt.want {
				t.Fatalf("meter skips the quota = %v, want %v", got, tt.want)
			}
			if got := tt.guard.Enforcing(); got != tt.want {
				t.Fatalf("guard enforces = %v, want %v", got, tt.want)
			}
		})
	}
}
