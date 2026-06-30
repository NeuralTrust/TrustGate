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

package plugins

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func TestDecisionForMode(t *testing.T) {
	t.Parallel()

	if got := DecisionForMode(policy.ModeEnforce); got != "block" {
		t.Fatalf("enforce = %q, want block", got)
	}
	if got := DecisionForMode(policy.ModeObserve); got != "observe" {
		t.Fatalf("observe = %q, want observe", got)
	}
}

func TestSpanDecisionFromOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		outcome string
		want    string
	}{
		{outcome: "blocked", want: "block"},
		{outcome: "block", want: "block"},
		{outcome: "reported", want: "reported"},
		{outcome: "report", want: "reported"},
		{outcome: "rejected", want: "reported"},
		{outcome: "allowed", want: "allowed"},
		{outcome: "failed_open", want: "failed_open"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.outcome, func(t *testing.T) {
			t.Parallel()
			if got := SpanDecisionFromOutcome(tc.outcome); got != tc.want {
				t.Fatalf("SpanDecisionFromOutcome(%q) = %q, want %q", tc.outcome, got, tc.want)
			}
		})
	}
}
