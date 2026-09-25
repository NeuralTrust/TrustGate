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

package googlemodelarmor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func streamSettings(over map[string]any) map[string]any {
	stream := map[string]any{"enabled": true}
	for k, v := range over {
		stream[k] = v
	}
	set := modelArmorSettings()
	set["streaming"] = stream
	return set
}

func anonymizeStreamSettings() map[string]any {
	set := streamSettings(nil)
	set["sdp_action"] = sdpActionAnonymize
	return set
}

func segment(seq int, accumulated string) appplugins.StreamSegment {
	return appplugins.StreamSegment{StreamID: "s-1", Seq: seq, Accumulated: accumulated}
}

func streamInput(mode policy.Mode, set map[string]any, event *metrics.EventContext) appplugins.ExecInput {
	in := execInput(policy.StagePreResponse, mode, set, reqCtx(openAIRequest()), nil)
	in.Event = event
	return in
}

func newStreamEvent() (*metrics.EventContext, *trace.Span) {
	tr := trace.New("", trace.Metadata{})
	span := tr.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func TestStreamSettingsOptIn(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, nil)
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"absent block", modelArmorSettings(), false},
		{"enabled", streamSettings(nil), true},
		{"explicitly disabled", streamSettings(map[string]any{"enabled": false}), false},
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

func TestStreamSettingsDefaultsToFailClosed(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, nil)
	on, opts := p.StreamSettings(streamSettings(nil))
	if !on {
		t.Fatal("expected the opt-in")
	}
	if opts.OnError != "fail_closed" {
		t.Errorf("OnError = %q, want fail_closed: the buffered leg fails closed too", opts.OnError)
	}
}

func TestInspectSegmentAllowsCleanText(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "a clean paragraph"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block || got.HasTransform {
		t.Errorf("clean text must pass, got %+v", got)
	}
	if stub.count() != 1 {
		t.Errorf("sanitize calls = %d, want 1", stub.count())
	}
}

// Model Armor has no streaming sanitize method, which is why the plugin used to
// sit streaming out. A block is an ordinary sanitize call over the prefix.
func TestInspectSegmentCallsTheResponseEndpointWithThePrefix(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)

	seg := appplugins.StreamSegment{
		StreamID: "s-1", Seq: 2,
		Text:        "only this delta",
		Accumulated: "everything produced so far",
	}
	if _, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), seg); err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}

	if !strings.HasSuffix(stub.path(), ":sanitizeModelResponse") {
		t.Errorf("path = %q, want the model-response endpoint", stub.path())
	}
	var body map[string]any
	if err := json.Unmarshal(stub.lastBody, &body); err != nil {
		t.Fatalf("decoding the sanitize body: %v", err)
	}
	if got := body["modelResponseData"]; got != nil {
		data, _ := got.(map[string]any)
		if data["text"] != "everything produced so far" {
			t.Errorf("sanitized text = %v, want the accumulated prefix", data["text"])
		}
	} else {
		t.Fatalf("body carries no modelResponseData: %v", body)
	}
}

// SanitizeModelResponse correlates the response against the prompt that asked
// for it, so dropping the prompt changes what the filters conclude.
func TestInspectSegmentSendsTheCorrelationPrompt(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)

	if _, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "an answer")); err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(stub.lastBody, &body); err != nil {
		t.Fatalf("decoding the sanitize body: %v", err)
	}
	if _, ok := body["userPrompt"]; !ok {
		t.Errorf("body carries no userPrompt: %v", body)
	}
}

func TestInspectSegmentBlocks(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(3, "unsafe output"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if !got.Block {
		t.Fatal("a matching filter must stop the stream")
	}
	if got.Type != typeModelArmorBlocked {
		t.Errorf("Type = %q, want %q", got.Type, typeModelArmorBlocked)
	}
	if got.HasTransform {
		t.Error("a block is not a transform")
	}
}

func TestInspectSegmentAnonymisesAsATransform(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, sdpAnonymizeResponse("write to [EMAIL] soon"))
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, anonymizeStreamSettings(), nil),
		segment(2, "write to a@b.com soon"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block {
		t.Error("a maskable finding must not end the stream")
	}
	if !got.HasTransform || got.Transformed != "write to [EMAIL] soon" {
		t.Errorf("verdict = %+v, want the masked prefix as a transform", got)
	}
}

// inspectSDP only reports an anonymise when de-identified text came back, so a
// match with nothing to mask with arrives here already downgraded to a block.
// What matters either way is that the unmasked prefix is not released; the
// backstop in InspectSegment covers the same condition if that ever changes.
func TestInspectSegmentCutsWhenAnonymisationProducedNothing(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, sdpAnonymizeResponse(""))
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, anonymizeStreamSettings(), nil),
		segment(2, "write to a@b.com soon"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if !got.Block {
		t.Fatal("releasing the unmasked text is the one outcome the policy ruled out")
	}
	if got.HasTransform {
		t.Error("there is nothing to transform with")
	}
	if got.Transformed != "" {
		t.Errorf("Transformed = %q, want nothing to release", got.Transformed)
	}
}

func TestInspectSegmentReturnsTheCallFailure(t *testing.T) {
	t.Parallel()
	boom := errors.New("token source is down")
	p := pluginWithClientError(boom)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(6, "some text"))

	if err == nil {
		t.Fatal("a failed sanitize must reach the guard as an error")
	}
	if got != nil {
		t.Errorf("verdict = %+v, want nil so the guard resolves on_error", got)
	}
	if !strings.Contains(err.Error(), "block 6") {
		t.Errorf("error %q does not name the block", err)
	}
}

func TestInspectSegmentIsInertWithoutTheOptIn(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, modelArmorSettings(), nil), segment(1, "unsafe output"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block {
		t.Error("a policy that did not opt in must not cut")
	}
	if stub.count() != 0 {
		t.Errorf("sanitize calls = %d, want none", stub.count())
	}
}

func TestInspectSegmentSkipsEmptyText(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "  \n "))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block || stub.count() != 0 {
		t.Errorf("whitespace must cost no call, got %+v after %d calls", got, stub.count())
	}
}

func TestClosingSegmentPublishesTheStreamAccount(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	p := pluginWithStub(stub)
	event, span := newStreamEvent()

	if _, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), event),
		appplugins.StreamSegment{
			StreamID: "s-1", Closing: true,
			Report: appplugins.StreamReport{
				Evals: 6, GuardCalls: 5, CutAtEval: 4, CutOffsetChars: 512,
				GuardLatency: 1200 * time.Millisecond,
			},
		}); err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if stub.count() != 0 {
		t.Errorf("the closing segment asks for no verdict, got %d calls", stub.count())
	}

	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok {
		t.Fatalf("extras = %T, want *Data", span.PluginAttrsCopy().Extras)
	}
	if data.Streaming == nil {
		t.Fatal("no streaming block published")
	}
	if !data.Streaming.Enabled || data.Streaming.EvalsTotal != 6 || data.Streaming.GuardCalls != 5 {
		t.Errorf("counters = %+v", data.Streaming)
	}
	if data.Streaming.CutAtEval != 4 || data.Streaming.CutOffsetChars != 512 {
		t.Errorf("cut = %d@%d, want 4@512", data.Streaming.CutAtEval, data.Streaming.CutOffsetChars)
	}
	if data.Streaming.GuardLatencyMsTotal != 1200 {
		t.Errorf("latency = %d, want 1200", data.Streaming.GuardLatencyMsTotal)
	}
	if data.Decision != decisionBlocked {
		t.Errorf("Decision = %q, want %q for a cut stream", data.Decision, decisionBlocked)
	}
	if data.Template != "tmpl-1" {
		t.Errorf("Template = %q, want the configured one", data.Template)
	}
}

func TestClosingSegmentDecisionFollowsTheOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		report   appplugins.StreamReport
		findings []appplugins.StreamFinding
		want     string
	}{
		{"clean", appplugins.StreamReport{Evals: 3, GuardCalls: 3}, nil, decisionAllowed},
		{
			"reported but not cut",
			appplugins.StreamReport{Evals: 3, GuardCalls: 3},
			[]appplugins.StreamFinding{{Entry: "p", Fingerprint: "abcd"}},
			decisionReported,
		},
		{"cut", appplugins.StreamReport{Evals: 2, CutAtEval: 1}, nil, decisionBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
			event, span := newStreamEvent()

			if _, err := p.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, streamSettings(nil), event),
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
		})
	}
}

// SDP reports the types it found in the text it was given, so the set grows
// with the prefix. One key per type keeps each incident at one key however many
// blocks carry it.
func TestFindingFingerprintsAreOnePerInfoType(t *testing.T) {
	t.Parallel()
	one := findingFingerprints(policy.ModeObserve, &finding{filter: "sdp", infoTypes: []string{"EMAIL_ADDRESS"}})
	two := findingFingerprints(policy.ModeObserve,
		&finding{filter: "sdp", infoTypes: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}})

	if len(one) != 1 || len(two) != 2 {
		t.Fatalf("keys = %d and %d, want 1 and 2", len(one), len(two))
	}
	if two[0] != one[0] && two[1] != one[0] {
		t.Error("the email key must survive the phone number appearing in a later block")
	}
}

func TestFindingFingerprintsIgnoreInfoTypeOrder(t *testing.T) {
	t.Parallel()
	a := findingFingerprints(policy.ModeObserve,
		&finding{filter: "sdp", infoTypes: []string{"EMAIL_ADDRESS", "PHONE_NUMBER"}})
	b := findingFingerprints(policy.ModeObserve,
		&finding{filter: "sdp", infoTypes: []string{"PHONE_NUMBER", "EMAIL_ADDRESS"}})

	if len(a) != len(b) || a[0] != b[0] || a[1] != b[1] {
		t.Errorf("order changed the keys: %v vs %v", a, b)
	}
}

// confidence is a degree of belief over the text the call carried, so it can
// move between buckets as the prefix grows.
func TestFindingFingerprintsIgnoreConfidence(t *testing.T) {
	t.Parallel()
	low := findingFingerprints(policy.ModeObserve,
		&finding{filter: "rai", category: "hate_speech", confidence: "LOW"})
	high := findingFingerprints(policy.ModeObserve,
		&finding{filter: "rai", category: "hate_speech", confidence: "HIGH"})

	if len(low) != 1 || low[0] != high[0] {
		t.Errorf("confidence split one incident in two: %v vs %v", low, high)
	}

	// SDP reports no confidence today, so the per-info-type branch would not
	// notice confidence creeping into its key until a filter reported both.
	lowTyped := findingFingerprints(policy.ModeObserve,
		&finding{filter: "sdp", infoTypes: []string{"EMAIL_ADDRESS"}, confidence: "LOW"})
	highTyped := findingFingerprints(policy.ModeObserve,
		&finding{filter: "sdp", infoTypes: []string{"EMAIL_ADDRESS"}, confidence: "HIGH"})
	if len(lowTyped) != 1 || lowTyped[0] != highTyped[0] {
		t.Errorf("confidence split one typed incident in two: %v vs %v", lowTyped, highTyped)
	}
}

func TestFindingFingerprintsSeparateFilterAndCategory(t *testing.T) {
	t.Parallel()
	base := findingFingerprints(policy.ModeObserve, &finding{filter: "rai", category: "hate_speech"})
	for _, other := range []*finding{
		{filter: "pi_and_jailbreak", category: "hate_speech"},
		{filter: "rai", category: "harassment"},
	} {
		got := findingFingerprints(policy.ModeObserve, other)
		if got[0] == base[0] {
			t.Errorf("%+v folded into the same key as the base finding", other)
		}
	}
}

func TestFindingFingerprintsSkipBlockingModesAndNilFindings(t *testing.T) {
	t.Parallel()
	f := &finding{filter: "rai", category: "hate_speech"}
	if got := findingFingerprints(policy.ModeEnforce, f); got != nil {
		t.Errorf("a blocking mode stops the stream, nothing to deduplicate, got %v", got)
	}
	if got := findingFingerprints(policy.ModeObserve, nil); got != nil {
		t.Errorf("findingFingerprints(nil) = %v, want nil", got)
	}
}
