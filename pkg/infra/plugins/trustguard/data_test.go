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

package trustguard

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func TestGuardFindingJSONRoundTrip(t *testing.T) {
	t.Parallel()

	raw := `{"source":{"kind":"gate","gate_name":"max_tokens","policy_id":"pol-1"},"signal":{"type":"gate_block"},"outcome":{"action":"block"},"evidence":{"matched":"true"}}`
	var f GuardFinding
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.Source == nil || f.Source.Kind != "gate" || f.Source.GateName != "max_tokens" || f.Source.PolicyID != "pol-1" {
		t.Fatalf("source = %+v", f.Source)
	}
	if f.Signal == nil || f.Signal.Type != "gate_block" {
		t.Fatalf("signal = %+v", f.Signal)
	}
	if f.Outcome == nil || f.Outcome.Action != "block" {
		t.Fatalf("outcome = %+v", f.Outcome)
	}
	if f.Evidence["matched"] != "true" {
		t.Fatalf("evidence = %+v", f.Evidence)
	}

	encoded, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var again GuardFinding
	if err := json.Unmarshal(encoded, &again); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if again.Source == nil || again.Source.GateName != "max_tokens" {
		t.Fatalf("round-trip source = %+v", again.Source)
	}
}

func TestGuardOutcomeDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status string
		mode   policy.Mode
		want   string
	}{
		{status: statusBlock, mode: policy.ModeEnforce, want: decisionBlocked},
		{status: statusBlock, mode: policy.ModeObserve, want: decisionReported},
		{status: statusReport, mode: policy.ModeEnforce, want: decisionReported},
		{status: "allowed", mode: policy.ModeEnforce, want: decisionAllowed},
		{status: "", mode: policy.ModeEnforce, want: decisionAllowed},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.status+"_"+string(tc.mode), func(t *testing.T) {
			t.Parallel()
			if got := guardOutcomeDecision(tc.status, tc.mode); got != tc.want {
				t.Fatalf("guardOutcomeDecision(%q, %q) = %q, want %q", tc.status, tc.mode, got, tc.want)
			}
		})
	}
}
