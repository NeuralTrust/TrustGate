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

package regexreplace

import (
	"context"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

func cardRule() map[string]any {
	return map[string]any{"pattern": `\d{16}`, "replacement": "[CARD]"}
}

func emailRule() map[string]any {
	return map[string]any{"pattern": `\S+@\S+\.\w+`, "replacement": "[EMAIL]"}
}

func streamSettings(target string, rules ...map[string]any) map[string]any {
	set := settings(target, rules...)
	set["streaming"] = map[string]any{"enabled": true}
	return set
}

func segment(seq int, accumulated string) appplugins.StreamSegment {
	return appplugins.StreamSegment{StreamID: "s-1", Seq: seq, Accumulated: accumulated}
}

func streamInput(mode policy.Mode, set map[string]any, event *metrics.EventContext) appplugins.ExecInput {
	return execInput(policy.StagePreResponse, mode, set, nil, nil, event)
}

func TestStreamSettingsOptIn(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"absent block", settings(targetResponse, cardRule()), false},
		{"enabled on the response", streamSettings(targetResponse, cardRule()), true},
		{
			"enabled on the request",
			streamSettings(targetRequest, cardRule()),
			false,
		},
		{
			"explicitly disabled",
			map[string]any{"target": targetResponse, "rules": []map[string]any{cardRule()},
				"streaming": map[string]any{"enabled": false}},
			false,
		},
		{
			"enabled but the settings do not parse",
			map[string]any{"streaming": map[string]any{"enabled": true}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := p.StreamSettings(tc.settings)
			if got != tc.want {
				t.Errorf("StreamSettings() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInspectSegmentRewritesAsATransform(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(targetResponse, cardRule()), nil),
		segment(2, "the card is 4111111111111111 ok"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block {
		t.Error("this plugin rewrites, it never blocks")
	}
	if !got.HasTransform || got.Transformed != "the card is [CARD] ok" {
		t.Errorf("verdict = %+v, want the masked prefix", got)
	}
}

// A pattern can straddle a block boundary, so the delta alone matches nothing.
func TestInspectSegmentMatchesAcrossBlockBoundaries(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)

	seg := appplugins.StreamSegment{
		StreamID: "s-1", Seq: 2,
		Text:        "1111111111",
		Accumulated: "the card is 411111" + "1111111111",
	}
	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(targetResponse, cardRule()), nil), seg)

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if !got.HasTransform {
		t.Fatal("a number split across two deltas must still be masked")
	}
	if got.Transformed != "the card is [CARD]" {
		t.Errorf("Transformed = %q", got.Transformed)
	}
}

// The guard cannot tell "nothing matched" from "a mask I already applied came
// back unchanged", so it ends the stream on a transform that changes nothing.
// Reporting no match is what keeps a clean response streaming.
func TestInspectSegmentReportsNoTransformWhenNothingMatched(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(targetResponse, cardRule()), nil),
		segment(1, "nothing sensitive here"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.HasTransform {
		t.Error("an unchanged prefix must not be returned as a transform")
	}
	if got.Transformed != "" {
		t.Errorf("Transformed = %q, want empty", got.Transformed)
	}
	if got.Block {
		t.Error("a clean block must not end the stream")
	}
}

func TestInspectSegmentIsInertWithoutTheOptIn(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, settings(targetResponse, cardRule()), nil),
		segment(1, "the card is 4111111111111111"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.HasTransform || got.Block {
		t.Errorf("a policy that did not opt in must do nothing, got %+v", got)
	}
}

func TestInspectSegmentIgnoresARequestTargetedPolicy(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(targetRequest, cardRule()), nil),
		segment(1, "the card is 4111111111111111"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.HasTransform {
		t.Error("a request-targeted policy must not rewrite the response")
	}
}

// Unlike the guardrail plugins, this one reports in every mode: it never ends a
// stream, so enforce keeps calling and the set is what says the response was
// rewritten at all.
func TestRuleFingerprintsAreReportedInEveryMode(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)

	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		got, err := p.InspectSegment(context.Background(),
			streamInput(mode, streamSettings(targetResponse, cardRule()), nil),
			segment(1, "the card is 4111111111111111"))
		if err != nil {
			t.Fatalf("InspectSegment(%s): %v", mode, err)
		}
		if len(got.Fingerprints) != 1 {
			t.Errorf("mode %s reported %d fingerprints, want 1", mode, len(got.Fingerprints))
		}
	}
}

func TestRuleFingerprintsNameTheMatchingRulesOnly(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(streamSettings(targetResponse, cardRule(), emailRule()))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	onlyCard := ruleFingerprints(cfg, "the card is 4111111111111111")
	onlyEmail := ruleFingerprints(cfg, "write to a@b.com")
	both := ruleFingerprints(cfg, "4111111111111111 and a@b.com")
	none := ruleFingerprints(cfg, "nothing here")

	if len(onlyCard) != 1 || len(onlyEmail) != 1 || len(both) != 2 {
		t.Fatalf("counts = %d, %d, %d; want 1, 1, 2", len(onlyCard), len(onlyEmail), len(both))
	}
	if onlyCard[0] == onlyEmail[0] {
		t.Error("two rules must not fold into one key")
	}
	if none != nil {
		t.Errorf("ruleFingerprints() = %v, want nil when nothing matched", none)
	}
}

// Two rules can share a pattern with different replacements, and an operator
// reading the set needs to know which one fired.
func TestRuleFingerprintsSeparateRulesSharingAPattern(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(streamSettings(targetResponse,
		map[string]any{"pattern": `\d{16}`, "replacement": "[A]"},
		map[string]any{"pattern": `\d{16}`, "replacement": "[B]"},
	))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	got := ruleFingerprints(cfg, "4111111111111111")
	if len(got) != 2 || got[0] == got[1] {
		t.Errorf("ruleFingerprints() = %v, want two distinct keys", got)
	}
}

func TestClosingSegmentPublishesTheStreamAccount(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)
	event, span := newEvent()

	if _, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(targetResponse, cardRule()), event),
		appplugins.StreamSegment{
			StreamID: "s-1", Closing: true,
			Findings: []appplugins.StreamFinding{{Entry: "p", Fingerprint: "abcd"}},
			Report: appplugins.StreamReport{
				Evals: 5, GuardCalls: 5, GuardLatency: 40 * time.Millisecond,
			},
		}); err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}

	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok {
		t.Fatalf("extras = %T, want *Data", span.PluginAttrsCopy().Extras)
	}
	if data.Streaming == nil || !data.Streaming.Enabled || data.Streaming.EvalsTotal != 5 {
		t.Fatalf("streaming block = %+v", data.Streaming)
	}
	if !data.Changed {
		t.Error("a stream that reported a rewrite must not publish changed: false")
	}
	if data.Decision != decisionRewritten {
		t.Errorf("Decision = %q, want %q", data.Decision, decisionRewritten)
	}
}

func TestClosingSegmentDecisionFollowsTheOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		report   appplugins.StreamReport
		findings []appplugins.StreamFinding
		want     string
		changed  bool
	}{
		{"nothing matched", appplugins.StreamReport{Evals: 4, GuardCalls: 4}, nil, decisionNoMatch, false},
		{
			"rewritten",
			appplugins.StreamReport{Evals: 4, GuardCalls: 4},
			[]appplugins.StreamFinding{{Entry: "p", Fingerprint: "abcd"}},
			decisionRewritten, true,
		},
		{
			"the rewrite could not be applied",
			appplugins.StreamReport{Evals: 3, CutAtEval: 2},
			nil, decisionRewriteUnapplied, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New(nil, nil)
			event, span := newEvent()

			if _, err := p.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, streamSettings(targetResponse, cardRule()), event),
				appplugins.StreamSegment{
					StreamID: "s-1", Closing: true, Report: tc.report, Findings: tc.findings,
				}); err != nil {
				t.Fatalf("InspectSegment: %v", err)
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			if !ok {
				t.Fatalf("extras = %T", span.PluginAttrsCopy().Extras)
			}
			if data.Decision != tc.want {
				t.Errorf("Decision = %q, want %q", data.Decision, tc.want)
			}
			if data.Changed != tc.changed {
				t.Errorf("Changed = %v, want %v", data.Changed, tc.changed)
			}
		})
	}
}
