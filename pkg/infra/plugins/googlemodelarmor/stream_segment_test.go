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
	p := New(adapter.NewRegistry(), "", 0, true, nil)
	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"absent block: on by default", modelArmorSettings(), true},
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

func TestStreamSettingsDefaultsToFailOpen(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, true, nil)
	for name, set := range map[string]map[string]any{
		"enabled, nothing else": streamSettings(nil),
		"no streaming block":    modelArmorSettings(),
	} {
		on, opts := p.StreamSettings(set)
		if !on {
			t.Fatalf("%s: expected the opt-in", name)
		}
		if opts.OnError != "fail_open" {
			t.Errorf("%s: OnError = %q, want fail_open: a Model Armor outage must not cut a stream", name, opts.OnError)
		}
	}
}

func TestStreamSettingsIgnoreAStoredFailClosed(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, true, nil)
	on, opts := p.StreamSettings(streamSettings(map[string]any{"on_error": "fail_closed", "guard_timeout": "1ms"}))
	if !on || opts.OnError != "fail_open" {
		t.Errorf("on=%v OnError=%q, want a stored fail_closed to be ignored", on, opts.OnError)
	}
}

func TestStreamSettingsDefaultsFitTheProviderLimit(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, true, nil)
	_, opts := p.StreamSettings(modelArmorSettings())
	// 65,536 tokens at about 4 characters each is the documented screening limit.
	if opts.MaxAccumulatedBytes > 65536*4 {
		t.Errorf("MaxAccumulatedBytes = %d, above the documented 262144", opts.MaxAccumulatedBytes)
	}
}

func TestStreamSettingsStaysWithinTheSanitizeLimit(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, true, nil)
	cases := []struct {
		name     string
		settings map[string]any
		want     int
	}{
		{"default", streamSettings(nil), 57344},
		{"configured below the limit", streamSettings(map[string]any{"max_accumulated_bytes": 8192}), 8192},
		{"configured above the limit", streamSettings(map[string]any{"max_accumulated_bytes": 1048576}), 57344},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			on, opts := p.StreamSettings(tc.settings)
			if !on {
				t.Fatal("expected the opt-in")
			}
			if opts.MaxAccumulatedBytes != tc.want {
				t.Errorf("MaxAccumulatedBytes = %d, want %d: the block and the correlation prompt must fit 65,536 tokens",
					opts.MaxAccumulatedBytes, tc.want)
			}
		})
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
// That is a provider block verdict, not an unappliable mask, so it still cuts.
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
		t.Errorf("verdict = %+v, want nil so the executor absorbs the failure and fails open", got)
	}
	if !strings.Contains(err.Error(), "block 6") {
		t.Errorf("error %q does not name the block", err)
	}
}

// RUN-1667 on the streaming leg: a block_on filter absent from the response
// (a template that never enabled it) or an invocation that failed outright must
// reach the executor as an error, which fails open and is recorded, instead of
// releasing the block as clean.
func TestInspectSegmentFailsOpenWhenABlockOnFilterProducedNoVerdictForAvailability(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body, want string
	}{
		{"absent from template", sdpOnlyAllow, reasonFilterNotInTemplate},
		{"invocation failure", invocationFailureResponse, "invocationResult FAILURE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, http.StatusOK, tc.body))

			got, err := p.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(3, "some text"))

			if err == nil {
				t.Fatalf("expected an error for the guard, got verdict %+v", got)
			}
			if got != nil {
				t.Errorf("verdict = %+v, want nil so the executor absorbs the failure and fails open", got)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "block 3") {
				t.Errorf("error %q should name the block and %q", err, tc.want)
			}
		})
	}
}

// A mask in hand outranks a block_on filter the template never enabled in a
// blocking mode, as on the buffered leg: releasing the original text would send
// the raw PII the mask exists to hide, and the missing filter is the customer's
// configuration, not the content's. The incomplete verdict travels on the
// transform.
func TestInspectSegmentMasksWhenABlockOnFilterIsAbsentFromTheTemplate(t *testing.T) {
	t.Parallel()
	body := sanitizeOpen +
		`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":"write to [EMAIL] soon"}}}}` +
		sanitizeClose
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, body))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, anonymizeStreamSettings(), nil), segment(2, "write to a@b.com soon"))

	if err != nil {
		t.Fatalf("a usable mask must not become an error: %v", err)
	}
	if !got.HasTransform || got.Transformed != "write to [EMAIL] soon" {
		t.Fatalf("verdict = %+v, want the masked prefix as a transform", got)
	}
	var failure *appplugins.ExternalStreamFailure
	if !errors.As(got.Incomplete, &failure) || failure.Reason != appplugins.FailureVerdictIncomplete || failure.Detail != reasonFilterNotInTemplate {
		t.Fatalf("Incomplete = %v, want a typed verdict_incomplete/%s", got.Incomplete, reasonFilterNotInTemplate)
	}

	observed, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeObserve, anonymizeStreamSettings(), nil), segment(2, "write to a@b.com soon"))
	if err == nil {
		t.Fatalf("observe applies no mask, so the incomplete verdict stays an error, got %+v", observed)
	}
}

func TestInspectSegmentMatchWinsOverAbsentFilter(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, sdpOnlyRAIHits))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "some text"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if !got.Block {
		t.Errorf("a real match must block, got %+v", got)
	}
}

// block_on naming only what the template enables streams through.
func TestInspectSegmentIgnoresAbsentFilterNotInBlockOn(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, sdpOnlyAllow))

	settings := streamSettings(nil)
	settings["block_on"] = []string{filterSDP}
	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, settings, nil), segment(1, "some text"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block || got.HasTransform {
		t.Errorf("clean text must pass, got %+v", got)
	}
}

func TestInspectSegmentIsInertWhenStreamingIsOptedOut(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
	p := pluginWithStub(stub)

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, streamSettings(map[string]any{"enabled": false}), nil), segment(1, "unsafe output"))

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	if got.Block {
		t.Error("a policy that opted out must not cut")
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
		{"a failed block on an otherwise clean stream", appplugins.StreamReport{Evals: 3, GuardCalls: 2, FailedEvals: 1}, nil, "failed_open"},
		{
			"a finding outranks a missing inspection",
			appplugins.StreamReport{Evals: 3, GuardCalls: 2, FailedEvals: 1},
			[]appplugins.StreamFinding{{Entry: "p", Fingerprint: "abcd"}},
			decisionReported,
		},
		{"a cut outranks a failure", appplugins.StreamReport{Evals: 3, GuardCalls: 2, FailedEvals: 1, CutAtEval: 2}, nil, decisionBlocked},
		// RUN-1745 F7: a masked stream used to read allowed.
		{"masked", appplugins.StreamReport{Evals: 3, GuardCalls: 3, MaskedEvals: 2}, nil, decisionAnonymized},
		{"masked, then cut", appplugins.StreamReport{Evals: 3, CutAtEval: 3, MaskedEvals: 2}, nil, decisionBlocked},
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

// RUN-1710: the closing write carries the first failed block's reason whatever
// the decision settled on.
func TestClosingSegmentCarriesTheStreamFailure(t *testing.T) {
	t.Parallel()
	failed := func(r appplugins.StreamReport) appplugins.StreamReport {
		r.FailedEvals = 1
		r.FailureReason = appplugins.FailureVerdictIncomplete
		r.FailureDetail = "filter_not_executed"
		return r
	}
	cases := []struct {
		name         string
		report       appplugins.StreamReport
		wantDecision string
		wantReason   string
		wantDetail   string
	}{
		{"released after a failed block", failed(appplugins.StreamReport{Evals: 3, GuardCalls: 2}), "failed_open", "verdict_incomplete", "filter_not_executed"},
		{"a block after an earlier failure keeps the reason", failed(appplugins.StreamReport{Evals: 3, CutAtEval: 3}), decisionBlocked, "verdict_incomplete", "filter_not_executed"},
		{"no failure, no reason", appplugins.StreamReport{Evals: 3, GuardCalls: 3}, decisionAllowed, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
			event, span := newStreamEvent()

			if _, err := p.InspectSegment(context.Background(),
				streamInput(policy.ModeEnforce, streamSettings(nil), event),
				appplugins.StreamSegment{StreamID: "s-1", Closing: true, Report: tc.report}); err != nil {
				t.Fatalf("InspectSegment: %v", err)
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			if !ok {
				t.Fatalf("extras = %T", span.PluginAttrsCopy().Extras)
			}
			if data.Decision != tc.wantDecision {
				t.Errorf("Decision = %q, want %q", data.Decision, tc.wantDecision)
			}
			if data.FailureReason != tc.wantReason || data.FailureDetail != tc.wantDetail {
				t.Errorf("failure = %q/%q, want %q/%q", data.FailureReason, data.FailureDetail, tc.wantReason, tc.wantDetail)
			}
		})
	}
}

// A cut that is a mask over a confirmed finding stays blocked, flagged degraded.
func TestClosingSegmentFlagsAnUnappliedMaskCutAsBlockedAndDegraded(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	event, span := newStreamEvent()

	_, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, anonymizeStreamSettings(), event),
		appplugins.StreamSegment{StreamID: "s-1", Closing: true, Report: appplugins.StreamReport{
			Evals: 2, GuardCalls: 2, CutAtEval: 2, CutOnFailure: true,
			FailureReason: appplugins.FailureVerdictIncomplete, FailureDetail: reasonAnonymizeNoOutput,
			FailureClass: appplugins.FailureClassInput,
		}})

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok {
		t.Fatalf("extras = %T, want *Data", span.PluginAttrsCopy().Extras)
	}
	if data.Decision != decisionBlocked || !data.Degraded || data.DegradedReason != reasonAnonymizeNoOutput || data.FailureClass != "input" {
		t.Fatalf("extras = %+v, want blocked + degraded %q, class input", data, reasonAnonymizeNoOutput)
	}
}

// A cut that is an input failure with no finding behind it records failed_closed.
func TestClosingSegmentRecordsAnInputCutAsFailedClosed(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	event, span := newStreamEvent()

	_, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, anonymizeStreamSettings(), event),
		appplugins.StreamSegment{StreamID: "s-1", Closing: true, Report: appplugins.StreamReport{
			Evals: 2, GuardCalls: 1, CutAtEval: 2, CutOnFailure: true,
			FailureReason: appplugins.FailureVerdictIncomplete, FailureDetail: reasonFilterNotExecuted,
			FailureClass: appplugins.FailureClassInput,
		}})

	if err != nil {
		t.Fatalf("InspectSegment: %v", err)
	}
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	if !ok {
		t.Fatalf("extras = %T, want *Data", span.PluginAttrsCopy().Extras)
	}
	if data.Decision != appplugins.DecisionFailedClosed || data.Degraded || data.FailureClass != "input" {
		t.Fatalf("extras = %+v, want failed_closed, not degraded, class input", data)
	}
}
