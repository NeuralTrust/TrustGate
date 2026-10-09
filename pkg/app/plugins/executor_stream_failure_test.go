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
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RUN-1710: the typed error must print exactly what the fmt.Errorf it replaced
// printed, because the guard logs that text and operators grep it.
func TestWrapExternalStreamFailure_TextIsUnchangedAndTyped(t *testing.T) {
	t.Parallel()
	cause := errors.New("boom")
	tests := []struct {
		name   string
		detail string
		want   string
	}{
		{name: "without detail", want: "bedrock_guardrail: transport: boom"},
		{name: "with detail", detail: "automated_reasoning_policy", want: "bedrock_guardrail: transport (automated_reasoning_policy): boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := WrapExternalStreamFailure("bedrock_guardrail", FailureTransport, tt.detail, cause)

			assert.Equal(t, tt.want, err.Error())
			legacy := fmt.Errorf("%s: %s: %w", "bedrock_guardrail", FailureTransport, cause)
			if tt.detail != "" {
				legacy = fmt.Errorf("%s: %s (%s): %w", "bedrock_guardrail", FailureTransport, tt.detail, cause)
			}
			assert.Equal(t, legacy.Error(), err.Error())
			assert.ErrorIs(t, err, cause)
			var typed *ExternalStreamFailure
			require.ErrorAs(t, err, &typed)
			assert.Equal(t, FailureTransport, typed.Reason)
			assert.Equal(t, tt.detail, typed.Detail)
			assert.Equal(t, "bedrock_guardrail", typed.Plugin)
		})
	}
}

func spanFor(t *testing.T, rt *trace.RequestTrace, name string) *trace.Span {
	t.Helper()
	for _, span := range rt.Spans() {
		if span.Name == name {
			return span
		}
	}
	require.FailNow(t, "no span", name)
	return nil
}

func failureStreamCtx(t *testing.T) (context.Context, *trace.RequestTrace, func()) {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	ctx, publish := NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	return ctx, rt, publish
}

func failureInput(pols []*policy.Policy) StageInput {
	return StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}
}

func TestRunStreamSegment_ReportCarriesTheFirstFailureReason(t *testing.T) {
	t.Parallel()
	typed := func(reason FailureReason, detail string) error {
		return WrapExternalStreamFailure("stub", reason, detail, errors.New("provider down"))
	}
	tests := []struct {
		name       string
		mode       policy.Mode
		onError    string
		errs       []error
		wantReason FailureReason
		wantDetail string
		wantEvals  int
	}{
		{name: "enforce fail_open", mode: policy.ModeEnforce, onError: "fail_open",
			errs: []error{typed(FailureTransport, "")}, wantReason: FailureTransport, wantEvals: 1},
		{name: "observe", mode: policy.ModeObserve,
			errs: []error{typed(FailureVerdictIncomplete, "filter_x")}, wantReason: FailureVerdictIncomplete, wantDetail: "filter_x", wantEvals: 1},
		{name: "several blocks keep the first reason", mode: policy.ModeEnforce, onError: "fail_open",
			errs:       []error{typed(FailureVerdictIncomplete, "first"), typed(FailureTransport, "second"), typed(FailureConfigInvalid, "")},
			wantReason: FailureVerdictIncomplete, wantDetail: "first", wantEvals: 3},
		{name: "an untyped error records no reason", mode: policy.ModeEnforce, onError: "fail_open",
			errs: []error{errors.New("plain")}, wantEvals: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exec, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: tt.mode})
			if tt.onError != "" {
				withOnError(pols, "guard", tt.onError)
			}
			in := failureInput(pols)
			ctx, rt, publish := failureStreamCtx(t)
			runner, ok := exec.(*executor)
			require.True(t, ok)

			for i, err := range tt.errs {
				inspectors["guard"].err = err
				_, runErr := runner.RunStreamSegment(ctx, in, segment(i+1, false))
				require.NoError(t, runErr)
			}
			_, err := runner.RunStreamSegment(ctx, in, StreamSegment{StreamID: "stream-1", Seq: len(tt.errs), Closing: true})
			require.NoError(t, err)
			publish()

			report := lastSeen(t, inspectors["guard"]).Report
			assert.Equal(t, tt.wantEvals, report.FailedEvals)
			assert.Equal(t, tt.wantReason, report.FailureReason)
			assert.Equal(t, tt.wantDetail, report.FailureDetail)
			assert.Equal(t, DecisionFailedOpen, spanFor(t, rt, "guard").Plugin.Decision)
		})
	}
}

// An enforcing entry that asked for fail_closed (or nothing) hands the error to
// the guard; the reason must be recorded before it leaves, since the guard only
// sees text.
func TestRunStreamSegment_HandedBackFailureKeepsItsReasonAndOnlyTheAuthorOwnsTheCut(t *testing.T) {
	t.Parallel()
	exec, pols, inspectors := streamChain(t,
		entrySpec{slug: "a_other", mode: policy.ModeEnforce},
		entrySpec{slug: "b_strict", mode: policy.ModeEnforce},
	)
	runner, ok := exec.(*executor)
	require.True(t, ok)
	withOnError(pols, "b_strict", "fail_closed")
	inspectors["b_strict"].err = WrapExternalStreamFailure("stub", FailureTransport, "", errors.New("down"))
	in := failureInput(pols)
	ctx, _, publish := failureStreamCtx(t)
	defer publish()

	_, err := runner.RunStreamSegment(ctx, in, segment(1, false))
	require.Error(t, err)
	var typed *ExternalStreamFailure
	require.ErrorAs(t, err, &typed, "the wrap must stay reachable through the executor's own wrapping")
	_, err = runner.RunStreamSegment(ctx, in, StreamSegment{
		StreamID: "stream-1", Seq: 1, Closing: true,
		Report: StreamReport{Evals: 1, CutAtEval: 1, CutOnFailure: true},
	})
	require.NoError(t, err)

	strict := lastSeen(t, inspectors["b_strict"]).Report
	assert.True(t, strict.CutOnFailure, "the failing entry authored a failure cut")
	assert.Equal(t, FailureTransport, strict.FailureReason)
	other := lastSeen(t, inspectors["a_other"]).Report
	assert.False(t, other.CutOnFailure, "an entry that did not author the cut must not read it as its own")
	assert.Zero(t, other.CutAtEval)
	assert.Empty(t, other.FailureReason)
}

// A cut that is not a failure (a block, or a mask that could not land) never
// carries CutOnFailure to the entry that authored it.
func TestRunStreamSegment_CutWithoutFailureIsNotFailedClosed(t *testing.T) {
	t.Parallel()
	exec, pols, inspectors := streamChain(t,
		entrySpec{slug: "a_masker", mode: policy.ModeEnforce, verdict: &SegmentVerdict{HasTransform: true, Transformed: "masked"}},
	)
	runner, ok := exec.(*executor)
	require.True(t, ok)
	in := failureInput(pols)
	ctx, _, publish := failureStreamCtx(t)
	defer publish()

	_, err := runner.RunStreamSegment(ctx, in, segment(1, false))
	require.NoError(t, err)
	_, err = runner.RunStreamSegment(ctx, in, StreamSegment{
		StreamID: "stream-1", Seq: 1, Closing: true,
		Report: StreamReport{Evals: 1, CutAtEval: 1},
	})
	require.NoError(t, err)

	report := lastSeen(t, inspectors["a_masker"]).Report
	assert.Equal(t, 1, report.CutAtEval)
	assert.False(t, report.CutOnFailure)
}

// The closing segment is the only place an inspector writes its span. When that
// call itself fails the span still gets a decision, and the first failure's
// reason when one is known.
func TestRunStreamSegment_ClosingSegmentFailureRecordsADecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		mode         policy.Mode
		onError      string
		cutOnFailure bool
		blockErr     error
		want         string
		wantReason   string
	}{
		{name: "observe", mode: policy.ModeObserve, want: DecisionFailedOpen},
		{name: "enforce fail_open", mode: policy.ModeEnforce, onError: "fail_open",
			blockErr: WrapExternalStreamFailure("stub", FailureTransport, "", errors.New("down")),
			want:     DecisionFailedOpen, wantReason: "transport"},
		{name: "enforce fail_closed that cut the stream", mode: policy.ModeEnforce, onError: "fail_closed", cutOnFailure: true,
			blockErr: WrapExternalStreamFailure("stub", FailureVerdictIncomplete, "f", errors.New("down")),
			want:     DecisionFailedClosed, wantReason: "verdict_incomplete"},
		{name: "enforce fail_open ignores a failure cut", mode: policy.ModeEnforce, onError: "fail_open", cutOnFailure: true, want: DecisionFailedOpen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exec, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: tt.mode})
			if tt.onError != "" {
				withOnError(pols, "guard", tt.onError)
			}
			runner, ok := exec.(*executor)
			require.True(t, ok)
			in := failureInput(pols)
			ctx, rt, publish := failureStreamCtx(t)
			inspectors["guard"].err = tt.blockErr
			_, _ = runner.RunStreamSegment(ctx, in, segment(1, false))
			inspectors["guard"].err = nil
			inspectors["guard"].closedErr = errors.New("closing blew up")

			report := StreamReport{Evals: 1}
			if tt.cutOnFailure {
				report.CutAtEval, report.CutOnFailure = 1, true
			}
			_, err := runner.RunStreamSegment(ctx, in, StreamSegment{StreamID: "stream-1", Seq: 1, Closing: true, Report: report})
			require.NoError(t, err)
			publish()

			span := spanFor(t, rt, "guard")
			assert.Equal(t, tt.want, span.Plugin.Decision)
			if tt.wantReason == "" {
				return
			}
			extras, ok := span.Plugin.Extras.(map[string]any)
			require.True(t, ok)
			assert.Equal(t, tt.wantReason, extras["failure_reason"])
			assert.Equal(t, tt.want, extras["decision"])
		})
	}
}

// An unclaimed failure cut (no entry failed a handed-back call, as with the
// guard's tool-inspection failure) is left on the entries that could block, with
// CutOnFailure set, but none of them failed: FailedEvals stays zero so a plugin
// cannot read it as its own failed_closed. The closing-failure path obeys the
// same rule.
func TestRunStreamSegment_UnclaimedFailureCutIsNotAnEntrysFailure(t *testing.T) {
	t.Parallel()
	exec, pols, inspectors := streamChain(t,
		entrySpec{slug: "a_reader", mode: policy.ModeEnforce},
		entrySpec{slug: "b_reader", mode: policy.ModeEnforce},
	)
	runner, ok := exec.(*executor)
	require.True(t, ok)
	in := failureInput(pols)
	ctx, rt, publish := failureStreamCtx(t)
	inspectors["b_reader"].closedErr = errors.New("closing blew up")

	_, err := runner.RunStreamSegment(ctx, in, segment(1, false))
	require.NoError(t, err)
	_, err = runner.RunStreamSegment(ctx, in, StreamSegment{
		StreamID: "stream-1", Seq: 1, Closing: true,
		Report: StreamReport{Evals: 1, CutAtEval: 1, CutOnFailure: true},
	})
	require.NoError(t, err)
	publish()

	for _, slug := range []string{"a_reader", "b_reader"} {
		report := lastSeen(t, inspectors[slug]).Report
		assert.Equal(t, 1, report.CutAtEval)
		assert.True(t, report.CutOnFailure, "an unclaimed cut stays on the entries that could block")
		assert.Zero(t, report.FailedEvals, "neither entry's own call failed")
	}
	assert.Equal(t, DecisionFailedOpen, spanFor(t, rt, "b_reader").Plugin.Decision,
		"a closing failure on an entry that never failed is not failed_closed")
}

// A verdict that is usable but incomplete is applied, and its failure becomes
// the entry's first on the stream without counting as a failed call: the entry
// is not retired for it and the mask still reaches the client.
func TestRunStreamSegment_IncompleteVerdictIsKeptWithoutCountingAsAFailedCall(t *testing.T) {
	t.Parallel()
	incomplete := WrapExternalStreamFailure("stub", FailureVerdictIncomplete, "rai", errors.New("filter skipped"))
	exec, pols, inspectors := streamChain(t, entrySpec{
		slug: "guard", mode: policy.ModeEnforce,
		verdict: &SegmentVerdict{HasTransform: true, Transformed: "masked", Incomplete: incomplete},
	})
	withOnError(pols, "guard", "fail_open")
	in := failureInput(pols)
	ctx, _, publish := failureStreamCtx(t)
	runner, ok := exec.(*executor)
	require.True(t, ok)

	var outcome *SegmentOutcome
	for i := 1; i <= 4; i++ {
		got, err := runner.RunStreamSegment(ctx, in, segment(i, false))
		require.NoError(t, err)
		outcome = got
	}
	_, err := runner.RunStreamSegment(ctx, in, StreamSegment{StreamID: "stream-1", Seq: 4, Closing: true})
	require.NoError(t, err)
	publish()

	require.NotNil(t, outcome)
	assert.True(t, outcome.HasTransform, "the mask is applied on every block, the entry is never retired")
	report := lastSeen(t, inspectors["guard"]).Report
	assert.Equal(t, FailureVerdictIncomplete, report.FailureReason)
	assert.Equal(t, "rai", report.FailureDetail)
	assert.Zero(t, report.FailedEvals)
}
