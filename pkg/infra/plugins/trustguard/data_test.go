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
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
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

func TestScoreLabelWorthy(t *testing.T) {
	t.Parallel()
	for _, d := range []string{decisionBlocked, decisionReported, decisionTransformed} {
		if !scoreLabelWorthy(d) {
			t.Fatalf("scoreLabelWorthy(%q) = false, want true", d)
		}
	}
	for _, d := range []string{decisionAllowed, decisionFailedOpen, ""} {
		if scoreLabelWorthy(d) {
			t.Fatalf("scoreLabelWorthy(%q) = true, want false", d)
		}
	}
}

func TestPrimaryFinding(t *testing.T) {
	t.Parallel()
	block := &GuardFindingOutcome{Action: "block"}

	tests := []struct {
		name      string
		findings  []GuardFinding
		wantLabel string
		wantScore float64
		wantOK    bool
	}{
		{name: "no findings", findings: nil, wantOK: false},
		{
			name:     "signal without type is ignored",
			findings: []GuardFinding{{Signal: &GuardFindingSignal{Confidence: 0.9}}},
			wantOK:   false,
		},
		{
			name: "prefers enforced over higher-confidence unenforced",
			findings: []GuardFinding{
				{Signal: &GuardFindingSignal{Type: "toxicity", Confidence: 0.95}},
				{Signal: &GuardFindingSignal{Type: "prompt_injection", Confidence: 0.6}, Outcome: block},
			},
			wantLabel: "prompt_injection",
			wantScore: 0.6,
			wantOK:    true,
		},
		{
			name: "highest confidence among enforced",
			findings: []GuardFinding{
				{Signal: &GuardFindingSignal{Type: "toxicity", Confidence: 0.7}, Outcome: block},
				{Signal: &GuardFindingSignal{Type: "prompt_injection", Confidence: 0.9}, Outcome: block},
			},
			wantLabel: "prompt_injection",
			wantScore: 0.9,
			wantOK:    true,
		},
		{
			name: "falls back to highest confidence signal",
			findings: []GuardFinding{
				{Signal: &GuardFindingSignal{Type: "toxicity", Confidence: 0.4}},
				{Signal: &GuardFindingSignal{Type: "pii", Confidence: 0.8}},
			},
			wantLabel: "pii",
			wantScore: 0.8,
			wantOK:    true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			label, score, ok := primaryFinding(tc.findings)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if label != tc.wantLabel {
				t.Fatalf("label = %q, want %q", label, tc.wantLabel)
			}
			if score != tc.wantScore {
				t.Fatalf("score = %v, want %v", score, tc.wantScore)
			}
		})
	}
}

func TestRecordGuardOutcomeSetsScoreLabel(t *testing.T) {
	t.Parallel()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)

	recordGuardOutcome(metrics.NewEventContext(span), guardData{
		Decision: decisionBlocked,
		Findings: []GuardFinding{
			{Signal: &GuardFindingSignal{Type: "prompt_injection", Confidence: 0.93}, Outcome: &GuardFindingOutcome{Action: "block"}},
		},
	})

	attrs := span.PluginAttrsCopy()
	if attrs.ScoreLabel != "prompt_injection" {
		t.Fatalf("ScoreLabel = %q, want prompt_injection", attrs.ScoreLabel)
	}
	if attrs.Score == nil || *attrs.Score != 0.93 {
		t.Fatalf("Score = %v, want 0.93", attrs.Score)
	}
}

func TestRecordGuardOutcomeAllowedHasNoScoreLabel(t *testing.T) {
	t.Parallel()
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)

	recordGuardOutcome(metrics.NewEventContext(span), guardData{
		Decision: decisionAllowed,
		Findings: []GuardFinding{{Signal: &GuardFindingSignal{Type: "toxicity", Confidence: 0.9}}},
	})

	attrs := span.PluginAttrsCopy()
	if attrs.ScoreLabel != "" {
		t.Fatalf("ScoreLabel = %q, want empty", attrs.ScoreLabel)
	}
	if attrs.Score != nil {
		t.Fatalf("Score = %v, want nil", attrs.Score)
	}
}
