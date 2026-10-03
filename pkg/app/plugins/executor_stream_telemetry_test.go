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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func streamSpanCtx(t *testing.T) context.Context {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	ctx, publish := NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	t.Cleanup(publish)
	return ctx
}

func lastClosing(t *testing.T, stub *orderStub) StreamSegment {
	t.Helper()
	require.NotEmpty(t, stub.seen)
	seg := stub.seen[len(stub.seen)-1]
	require.True(t, seg.Closing)
	return seg
}

// RUN-1745 F6: a masker and an enforcing reader share a block and the reader's
// call fails. Under fail_closed the guard cuts for the failure, so the reader
// authored the cut; the cut used to be published against the masker, whose
// span read blocked while the failing policy's read allowed. When the cut is
// instead a mask fail_open could not land, it stays the masker's.
func TestRunStreamSegment_CutOnFailureBelongsToTheFailingEntry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		cutOnFailure bool
		wantMasker   int
		wantFailing  int
	}{
		{name: "a fail_closed cut is the failing entry's", cutOnFailure: true, wantFailing: 3},
		{name: "a mask that could not land is the masker's", wantMasker: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			exec, pols, stubs, _ := orderChain(t,
				orderSpec{slug: "a_moderation", priority: 10, mode: policy.ModeEnforce, reads: true, err: assert.AnError},
				orderSpec{slug: "z_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
			)
			in := StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}
			ctx := streamSpanCtx(t)

			out, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 3, Text: " 4111", Accumulated: "card 4111"})
			require.ErrorIs(t, err, assert.AnError)
			require.NotNil(t, out, "the mask travels with the failure")
			_, err = exec.RunStreamSegment(ctx, in, StreamSegment{
				StreamID: "s", Seq: 3, Closing: true,
				Report: StreamReport{Evals: 3, CutAtEval: 3, CutOnFailure: tt.cutOnFailure},
			})
			require.NoError(t, err)

			assert.Equal(t, tt.wantMasker, lastClosing(t, stubs["z_masker"]).Report.CutAtEval)
			assert.Equal(t, tt.wantFailing, lastClosing(t, stubs["a_moderation"]).Report.CutAtEval)
		})
	}
}

// RUN-1745 F7: a masked stream read as allowed because nothing on the closing
// segment said a mask had landed. Only an enforcing entry's mask counts, and
// not on a block another entry cut.
func TestRunStreamSegment_CountsTheMasksEachEntryHandedOn(t *testing.T) {
	t.Parallel()
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_masker", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
		orderSpec{slug: "b_observer", priority: 10, mode: policy.ModeObserve, rewrites: true, fn: replaceWith("card", "CARD")},
		orderSpec{slug: "c_blocker", priority: 20, mode: policy.ModeEnforce, fn: func(seg StreamSegment) *SegmentVerdict {
			if strings.Contains(seg.Accumulated, "STOP") {
				return &SegmentVerdict{Block: true, Type: "flagged"}
			}
			return nil
		}},
	)
	in := StageInput{Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{}}
	ctx := streamSpanCtx(t)

	for i, acc := range []string{"card 4111", "card **** 4111", "card **** **** 4111 STOP"} {
		out, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: i + 1, Text: " 4111", Accumulated: acc})
		require.NoError(t, err)
		require.NotNil(t, out)
	}
	_, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 3, Closing: true, Report: StreamReport{Evals: 3}})
	require.NoError(t, err)

	assert.Equal(t, 2, lastClosing(t, stubs["a_masker"]).Report.MaskedEvals, "the block the blocker cut discards its mask")
	assert.Zero(t, lastClosing(t, stubs["b_observer"]).Report.MaskedEvals, "an observe transform is never applied")
	assert.Zero(t, lastClosing(t, stubs["c_blocker"]).Report.MaskedEvals)
}
