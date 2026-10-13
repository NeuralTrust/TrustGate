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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withWindow(pol *policy.Policy, window int) {
	pol.Settings = map[string]any{"enabled": true, "max_accumulated_bytes": window}
}

func TestRunStreamSegment_EntryIsHandedOnlyItsOwnWindow(t *testing.T) {
	t.Parallel()
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_guard", priority: 10, mode: policy.ModeEnforce},
		orderSpec{slug: "b_remote", priority: 20, mode: policy.ModeEnforce, reads: true},
	)
	withWindow(pols[1], 5)
	seg := StreamSegment{StreamID: "s", Seq: 3, Text: " fin", Accumulated: "señal sí fin"}

	runOrder(t, exec, pols, seg)

	require.Len(t, stubs["a_guard"].seen, 1)
	assert.Equal(t, seg, stubs["a_guard"].seen[0], "an entry with no window of its own gets the stream's")
	require.Len(t, stubs["b_remote"].seen, 1)
	got := stubs["b_remote"].seen[0]
	assert.Equal(t, " fin", got.Accumulated, "the tail within 5 bytes, advanced past the rune it splits")
	assert.Equal(t, " fin", got.Text)
	assert.True(t, got.Truncated)
}

func TestRunStreamSegment_WindowedTransformKeepsTheHead(t *testing.T) {
	t.Parallel()
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_remote", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
		orderSpec{slug: "b_moderation", priority: 20, mode: policy.ModeEnforce, reads: true},
	)
	withWindow(pols[0], 9)
	seg := StreamSegment{StreamID: "s", Seq: 2, Text: " 4111", Accumulated: "4111 old card 4111"}

	out := runOrder(t, exec, pols, seg)

	require.True(t, out.HasTransform)
	assert.Equal(t, "4111 old card ****", out.Transformed,
		"the transform covers the window, and the head it never saw goes back in front unchanged")
	require.Len(t, stubs["b_moderation"].seen, 1)
	assert.Equal(t, "4111 old card ****", stubs["b_moderation"].seen[0].Accumulated)
	assert.Equal(t, " ****", stubs["b_moderation"].seen[0].Text)
}

func TestSegmentWithin(t *testing.T) {
	t.Parallel()
	seg := StreamSegment{Text: "lo", Accumulated: "hello"}
	tests := []struct {
		name     string
		seg      StreamSegment
		window   int
		wantAcc  string
		wantText string
		wantHead string
	}{
		{name: "no window", seg: seg, window: 0, wantAcc: "hello", wantText: "lo"},
		{name: "fits", seg: seg, window: 5, wantAcc: "hello", wantText: "lo"},
		{name: "tail", seg: seg, window: 3, wantAcc: "llo", wantText: "lo", wantHead: "he"},
		{name: "never cuts the block's own text", seg: seg, window: 1, wantAcc: "lo", wantText: "lo", wantHead: "hel"},
		{
			name:     "never opens mid-rune",
			seg:      StreamSegment{Text: "b", Accumulated: "a€b"},
			window:   2,
			wantAcc:  "b",
			wantText: "b",
			wantHead: "a€",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, head := segmentWithin(tt.seg, tt.window)
			assert.Equal(t, tt.wantAcc, got.Accumulated)
			assert.Equal(t, tt.wantText, got.Text)
			assert.Equal(t, tt.wantHead, head)
			assert.Equal(t, tt.wantHead != "", got.Truncated)
			assert.True(t, utf8.ValidString(got.Accumulated))
			assert.True(t, strings.HasSuffix(got.Accumulated, got.Text))
			assert.Equal(t, tt.seg.Accumulated, head+got.Accumulated)
		})
	}
}

func TestStagePlan_StreamPlan_KeepsTheLargestWindow(t *testing.T) {
	t.Parallel()
	pre := []policy.Stage{policy.StagePreResponse}
	reg := newRegistry(t, newStreamPlugin("bedrock", nil), newStreamPlugin("guard", nil))
	pols := policies(t,
		polSpec{slug: "bedrock", enabled: true, priority: 1, stages: pre},
		polSpec{slug: "guard", enabled: true, priority: 2, stages: pre},
	)
	pols[0].Settings = map[string]any{"enabled": true, "head_chars": 400, "max_accumulated_bytes": 24576}
	pols[1].Settings = map[string]any{"enabled": true, "head_chars": 64, "max_accumulated_bytes": 262144}

	ok, opts := NewStagePlan(reg, pols, nil).StreamPlan(policy.StagePreResponse)

	require.True(t, ok)
	assert.Equal(t, 400, opts.HeadChars, "the first owner still sets the head gate")
	assert.Equal(t, 262144, opts.MaxAccumulatedBytes,
		"a small provider window ahead of the guard must not shrink what the guard inspects")
}

// The block's own text is never cut from an entry: one larger than the entry's
// window is screened in chunks of the window that together cover all of it.
func TestRunStreamSegment_BlockLargerThanTheWindowIsScreenedInChunks(t *testing.T) {
	t.Parallel()
	exec, pols, stubs, _ := orderChain(t,
		orderSpec{slug: "a_remote", priority: 10, mode: policy.ModeEnforce, reads: true},
	)
	withWindow(pols[0], 4)
	seg := StreamSegment{StreamID: "s", Seq: 2, Text: " a burst", Accumulated: "earlier a burst"}

	runOrder(t, exec, pols, seg)

	seen := stubs["a_remote"].seen
	require.Len(t, seen, 2)
	var pieces []string
	for _, got := range seen {
		assert.LessOrEqual(t, len(got.Accumulated), 4, "no call is larger than the entry's window")
		assert.True(t, got.Truncated)
		pieces = append(pieces, got.Accumulated)
	}
	assert.ElementsMatch(t, []string{" a b", "urst"}, pieces, "text about to be released is never kept from the entry")
}

func TestRunStreamSegment_FailureAfterAWindowedMaskCarriesTheWholeMask(t *testing.T) {
	t.Parallel()
	exec, pols, _, _ := orderChain(t,
		orderSpec{slug: "a_remote", priority: 10, mode: policy.ModeEnforce, rewrites: true, fn: replaceWith("4111", "****")},
		orderSpec{slug: "b_moderation", priority: 20, mode: policy.ModeEnforce, reads: true, err: errors.New("provider down")},
	)
	withWindow(pols[0], 9)
	seg := StreamSegment{StreamID: "s", Seq: 2, Text: " 4111", Accumulated: "4111 old card 4111"}

	out, err := exec.RunStreamSegment(context.Background(), StageInput{
		Stage:    policy.StagePreResponse,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	}, seg)

	require.Error(t, err)
	require.NotNil(t, out, "fail_open must be able to release the masked text")
	assert.Equal(t, "4111 old card ****", out.Transformed)
}
