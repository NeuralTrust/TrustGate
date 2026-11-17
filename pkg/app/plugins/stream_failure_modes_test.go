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

package plugins

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// splitModesGuard decides a timeout and every other availability failure
// apart, as google_model_armor's failure_mode and timeout_failure_mode do. Its
// stream options say fail_closed, since some failure can be cut.
type splitModesGuard struct {
	chunkGuard
	closed, timeoutClosed bool
}

func (*splitModesGuard) StreamSettings(map[string]any) (bool, StreamOptions) {
	return true, StreamOptions{OnError: "fail_closed"}
}

func (g *splitModesGuard) StreamFailsClosedOn(_ map[string]any, _ FailureReason, detail string) bool {
	if detail == DetailTimeout {
		return g.timeoutClosed
	}
	return g.closed
}

func splitModesEntry(mode policy.Mode, closed, timeoutClosed bool) chainEntry {
	return chainEntry{
		plugin: &splitModesGuard{chunkGuard: chunkGuard{fakePlugin: fakePlugin{name: "guard"}}, closed: closed, timeoutClosed: timeoutClosed},
		mode:   mode,
	}
}

// A piece the block's deadline never let start is a timeout: an entry that
// blocks outages but lets slow answers through releases it, and records the
// timeout detail.
func TestMergeChunkVerdicts_ANeverStartedChunkFollowsTheTimeoutMode(t *testing.T) {
	t.Parallel()

	got, err := neverStartedMerge(splitModesEntry(policy.ModeEnforce, true, false), &SegmentVerdict{})
	assert.Nil(t, got)
	var typed *ExternalStreamFailure
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, FailureTransport, typed.Reason)
	assert.Equal(t, DetailTimeout, typed.Detail)
	assert.Equal(t, FailureClassAvailability, typed.Class)

	masked, err := neverStartedMerge(splitModesEntry(policy.ModeEnforce, true, false),
		&SegmentVerdict{HasTransform: true, Transformed: "01234{X}789"})
	require.NoError(t, err)
	require.NotNil(t, masked)
	assert.False(t, masked.Block)
	assert.True(t, masked.HasTransform)
	require.ErrorAs(t, masked.Incomplete, &typed)
	assert.Equal(t, DetailTimeout, typed.Detail)

	cut, err := neverStartedMerge(splitModesEntry(policy.ModeEnforce, false, true), &SegmentVerdict{})
	require.NoError(t, err)
	require.NotNil(t, cut)
	assert.True(t, cut.Block)
	require.NotNil(t, cut.Failure)
	assert.Equal(t, DetailTimeout, cut.Failure.Detail)

	observed, err := neverStartedMerge(splitModesEntry(policy.ModeObserve, false, true), &SegmentVerdict{})
	assert.Nil(t, observed)
	require.ErrorAs(t, err, &typed, "observe never cuts")
	assert.Equal(t, DetailTimeout, typed.Detail)
}

// A piece that failed fast (an outage, not a timeout) follows the other mode.
func TestMergeChunkVerdicts_AnOutageOnAPieceFollowsTheOtherMode(t *testing.T) {
	t.Parallel()
	outage := []error{nil, errors.New("connection refused")}
	verdicts := []*SegmentVerdict{{}, nil}

	cut, err := mergeOfEntry(splitModesEntry(policy.ModeEnforce, true, false), verdicts, outage)
	require.NoError(t, err)
	require.NotNil(t, cut)
	assert.True(t, cut.Block)
	require.NotNil(t, cut.Failure)
	assert.Empty(t, cut.Failure.Detail)

	released, err := mergeOfEntry(splitModesEntry(policy.ModeEnforce, false, true), verdicts, outage)
	assert.Nil(t, released)
	require.Error(t, err)
}

func TestChunkTimeout(t *testing.T) {
	t.Parallel()
	failed := func(i int) ChunkDecision {
		return ChunkDecision{Kind: ChunkAvailabilityFailure, Index: i, Reason: FailureTransport}
	}
	for _, tc := range []struct {
		name   string
		d      ChunkDecision
		out    textchunk.Outcome[struct{}]
		detail string
	}{
		{"never started", failed(0), textchunk.Outcome[struct{}]{}, DetailTimeout},
		{"cut by the deadline", failed(0), textchunk.Outcome[struct{}]{Started: true, BudgetCut: true}, DetailTimeout},
		{"ended on its own timeout", failed(0), textchunk.Outcome[struct{}]{Started: true, TimedOut: true}, DetailTimeout},
		{"a bare error in time", failed(0), textchunk.Outcome[struct{}]{Started: true}, ""},
		{"a named detail is kept", ChunkDecision{Kind: ChunkAvailabilityFailure, Reason: FailureTransport, Detail: DetailThrottled}, textchunk.Outcome[struct{}]{}, DetailThrottled},
		{"input is never a timeout", ChunkDecision{Kind: ChunkInputFailure, Reason: FailureInputTooLarge, Detail: DetailChunkBudget}, textchunk.Outcome[struct{}]{}, DetailChunkBudget},
		{"index out of range", failed(3), textchunk.Outcome[struct{}]{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.detail, ChunkTimeout(tc.d, []textchunk.Outcome[struct{}]{tc.out}).Detail)
		})
	}
}

func splitModesChain(t *testing.T, closed, timeoutClosed bool, fn func(StreamSegment) (*SegmentVerdict, error)) (*executor, StageInput) {
	t.Helper()
	g := &splitModesGuard{
		chunkGuard: chunkGuard{
			fakePlugin: fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}},
			fn:         fn,
		},
		closed:        closed,
		timeoutClosed: timeoutClosed,
	}
	pol := policies(t, polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}})[0]
	pol.Mode = policy.ModeEnforce
	pol.Settings = map[string]any{"enabled": true}
	exec, ok := NewExecutor(newRegistry(t, g), nil).(*executor)
	require.True(t, ok)
	return exec, failureInput([]*policy.Policy{pol})
}

// A block of ordinary size whose call failed with a failure the policy does not
// cut is absorbed as failed_open on the entry, as a fail_open guardrail's is,
// even though the entry's stream options say fail_closed for the failures it
// does cut. One it cuts is handed back to the guard as before.
func TestRunStreamSegment_AnEntryWithSplitModesAbsorbsTheFailuresItDoesNotCut(t *testing.T) {
	t.Parallel()
	timeout := newExternalStreamFailure("guard", FailureTransport, DetailTimeout, errors.New("slow"))
	outage := newExternalStreamFailure("guard", FailureTransport, "", errors.New("connection refused"))
	for _, tc := range []struct {
		name                  string
		closed, timeoutClosed bool
		err                   error
		handedBack            bool
	}{
		{"block outages, allow slow: a timeout is absorbed", true, false, timeout, false},
		{"allow outages, block slow: an outage is absorbed", false, true, outage, false},
		{"allow outages, block slow: a timeout is handed back", false, true, timeout, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exec, in := splitModesChain(t, tc.closed, tc.timeoutClosed, func(StreamSegment) (*SegmentVerdict, error) {
				return nil, tc.err
			})
			text := words(500)
			out, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})
			if tc.handedBack {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, out)
			assert.False(t, out.Block)
			assert.Equal(t, 1, out.FailedEntries)
		})
	}
}
