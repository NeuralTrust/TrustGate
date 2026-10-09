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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

func mergeEntry(mode policy.Mode) chainEntry {
	return chainEntry{plugin: &fakePlugin{name: "guard"}, mode: mode}
}

// mergeOf runs mergeChunkVerdicts over n chunks of 10 bytes each. A nil entry of
// errs means the call succeeded; started is true for every chunk, and the chunks
// from streamChunkParallel on waited behind the first round.
func mergeOf(mode policy.Mode, verdicts []*SegmentVerdict, errs []error) (*SegmentVerdict, error) {
	n := len(verdicts)
	chunks := make([]textchunk.Chunk, n)
	outs := make([]textchunk.Outcome[struct{}], n)
	var text strings.Builder
	for i := range chunks {
		chunks[i] = textchunk.Chunk{Start: i * 10, End: i*10 + 10, Text: "0123456789"}
		text.WriteString(chunks[i].Text)
		outs[i].Started = true
		outs[i].Waited = i >= streamChunkParallel
		if errs != nil {
			outs[i].Err = errs[i]
		}
	}
	return mergeChunkVerdicts(mergeEntry(mode), text.String(), chunks, verdicts, outs)
}

func inputFailure() *ExternalStreamFailure {
	return newExternalStreamFailure("guard", FailureVerdictIncomplete, DetailFilterNotExecuted, errors.New("filter did not run"))
}

func TestMergeChunkVerdicts_AnInputBlockOnChunkTwoBeatsAMaskOnChunkThree(t *testing.T) {
	t.Parallel()
	failure := inputFailure()
	verdicts := []*SegmentVerdict{
		{},
		{Block: true, Type: TypeGuardrailInputUninspectable, Message: DefaultUninspectableMessage, Failure: failure},
		{HasTransform: true, Transformed: "01234{X}789"},
		{},
	}

	got, err := mergeOf(policy.ModeEnforce, verdicts, nil)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Block)
	assert.Same(t, failure, got.Failure, "the cut carries the chunk's failure")
	assert.False(t, got.HasTransform, "a cut discards the masks of the block")
}

func TestMergeChunkVerdicts_AnInputTypedErrorInObserveIsReturnedAsItCame(t *testing.T) {
	t.Parallel()
	failure := inputFailure()
	verdicts := []*SegmentVerdict{{}, nil, {}, {}}
	errs := []error{nil, failure, nil, nil}

	got, err := mergeOf(policy.ModeObserve, verdicts, errs)

	assert.Nil(t, got)
	assert.Same(t, failure, err)
}

func TestMergeChunkVerdicts_AFindingOnChunkThreeBeatsAFailureVerdictOnChunkOne(t *testing.T) {
	t.Parallel()
	verdicts := []*SegmentVerdict{
		{Block: true, Type: TypeGuardrailInputUninspectable, Failure: inputFailure()},
		{},
		{Block: true, Type: "guardrail_blocked", Message: "no"},
		{},
	}

	got, err := mergeOf(policy.ModeEnforce, verdicts, nil)

	require.NoError(t, err)
	assert.True(t, got.Block)
	assert.Equal(t, "guardrail_blocked", got.Type)
	assert.Nil(t, got.Failure, "a finding is a verdict, a failure is not")
}

// Observe keeps what every chunk found: the verdict that decides carries the
// fingerprints of all the chunks that answered, not only its own.
func TestMergeChunkVerdicts_TheFingerprintsOfEveryChunkSurviveABlock(t *testing.T) {
	t.Parallel()
	incomplete := inputFailure()
	verdicts := []*SegmentVerdict{
		{Fingerprints: []string{"a"}, Incomplete: incomplete},
		{Fingerprints: []string{"b", "a"}},
		{Block: true, Type: "guardrail_blocked", Fingerprints: []string{"c"}},
		{Fingerprints: []string{"d"}},
	}

	got, err := mergeOf(policy.ModeObserve, verdicts, nil)

	require.NoError(t, err)
	assert.True(t, got.Block)
	assert.Equal(t, []string{"a", "b", "c", "d"}, got.Fingerprints)
	assert.Same(t, incomplete, got.Incomplete, "the first incomplete over every chunk that answered")
}

func TestMergeChunkVerdicts_AThrottleOnAFirstRoundChunkIsAvailability(t *testing.T) {
	t.Parallel()
	throttled := newExternalStreamFailure("guard", FailureTransport, DetailThrottled, errors.New("429"))
	verdicts := []*SegmentVerdict{{}, nil, {}, {}, {}, {}}
	errs := []error{nil, throttled, nil, nil, nil, nil}

	got, err := mergeOf(policy.ModeEnforce, verdicts, errs)

	assert.Nil(t, got)
	var typed *ExternalStreamFailure
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, DetailThrottled, typed.Detail)
	assert.Equal(t, FailureClassAvailability, typed.Class)
}

func TestMergeChunkVerdicts_AThrottleOnAChunkThatWaitedIsInput(t *testing.T) {
	t.Parallel()
	throttled := newExternalStreamFailure("guard", FailureTransport, DetailThrottled, errors.New("429"))
	verdicts := []*SegmentVerdict{{}, {}, {}, {}, {}, nil}
	errs := []error{nil, nil, nil, nil, nil, throttled}

	got, err := mergeOf(policy.ModeEnforce, verdicts, errs)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Block, "a request that large and throttled may be what throttled it")
	require.NotNil(t, got.Failure)
	assert.Equal(t, FailureInputTooLarge, got.Failure.Reason)
	assert.Equal(t, DetailThrottledOversize, got.Failure.Detail)

	_, err = mergeOf(policy.ModeObserve, verdicts, errs)
	var typed *ExternalStreamFailure
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, FailureClassInput, typed.Class)
	assert.Equal(t, DetailThrottledOversize, typed.Detail)
}

func TestMergeChunkVerdicts_AnExhaustedProviderQuotaFailsOpen(t *testing.T) {
	t.Parallel()
	quota := newExternalStreamFailure("guard", FailureConfigInvalid, DetailProviderQuotaExhausted, errors.New("insufficient_quota"))
	verdicts := []*SegmentVerdict{{}, nil, {}, {}}
	errs := []error{nil, quota, nil, nil}

	got, err := mergeOf(policy.ModeEnforce, verdicts, errs)

	assert.Nil(t, got)
	assert.Same(t, quota, err, "configuration is availability, whatever the number of chunks")
}

func TestRunStreamSegment_OnlyTheChunkThatEndsTheBlockIsFinal(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(40000)
	exec, in, guard := chunkChain(t, policy.ModeEnforce, window, allow)
	seg := StreamSegment{StreamID: "s", Seq: 7, Final: true, Text: text, Accumulated: text}

	_, err := exec.RunStreamSegment(context.Background(), in, seg)

	require.NoError(t, err)
	seen := guard.seen()
	require.Greater(t, len(seen), 1)
	finals, parts := 0, map[int]bool{}
	for _, s := range seen {
		assert.Equal(t, 7, s.Seq, "every piece is the same block")
		if s.Final {
			finals++
			assert.Equal(t, len(seen), s.Part, "the final piece is the last one")
			assert.True(t, strings.HasSuffix(text, s.Accumulated))
		}
		assert.Equal(t, len(seen), s.Parts)
		parts[s.Part] = true
	}
	assert.Equal(t, 1, finals, "the end of the response is reported once")
	assert.Len(t, parts, len(seen), "each piece has its own position")
}

// boundedGuard is an inspector that bounds its own payload.
type boundedGuard struct{ chunkGuard }

func (*boundedGuard) BoundsStreamPayload() bool { return true }

func TestRunStreamSegment_AnInspectorThatBoundsItsOwnPayloadIsNotSplit(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(40000)
	g := &boundedGuard{}
	g.fakePlugin = fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}}
	g.fn = allow
	pol := policies(t, polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}})[0]
	pol.Mode = policy.ModeEnforce
	pol.Settings = map[string]any{"enabled": true, "max_accumulated_bytes": window}
	exec, ok := NewExecutor(newRegistry(t, g), nil).(*executor)
	require.True(t, ok)
	ctx, _, publish := failureStreamCtx(t)
	seg := StreamSegment{StreamID: "s", Seq: 1, Final: true, Text: text, Accumulated: text}

	_, err := exec.RunStreamSegment(ctx, failureInput([]*policy.Policy{pol}), seg)
	require.NoError(t, err)
	_, err = exec.RunStreamSegment(ctx, failureInput([]*policy.Policy{pol}), StreamSegment{StreamID: "s", Seq: 2, Closing: true})
	require.NoError(t, err)
	publish()

	seen := g.seen()
	require.Len(t, seen, 1, "one call for the whole block")
	assert.Len(t, seen[0].Accumulated, len(text))
	assert.True(t, seen[0].Final)
	assert.Zero(t, seen[0].Parts)
	assert.Zero(t, g.last.ChunkedEvals)
}

func TestRunStreamSegment_ABlockRefusedForItsSizeIsNotCountedAsChunked(t *testing.T) {
	t.Parallel()
	const window = 8192
	text := words(100000)
	require.Greater(t, textchunk.Count(text, streamChunkSpec(window)), maxStreamChunks)
	exec, in, guard := chunkChain(t, policy.ModeEnforce, window, allow)
	ctx, _, publish := failureStreamCtx(t)

	_, err := exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})
	require.NoError(t, err)
	_, err = exec.RunStreamSegment(ctx, in, StreamSegment{StreamID: "s", Seq: 2, Closing: true})
	require.NoError(t, err)
	publish()

	assert.Empty(t, guard.seen())
	assert.Zero(t, guard.last.ChunkedEvals, "a block that was refused was never screened in chunks")
}

// A window is an operator's setting, so any size must make a spec Split accepts,
// and a window that holds a long secret shares enough to keep it whole.
func TestStreamChunkSpecIsValidForEveryWindow(t *testing.T) {
	t.Parallel()
	for window := 1; window <= 300; window++ {
		spec := streamChunkSpec(window)
		assert.NotPanics(t, func() { textchunk.Split(words(1000), spec) }, "window %d", window)
	}
	for _, window := range []int{8 << 10, 32<<10 - 1, 32 << 10, 56 << 10, 64 << 10, 256 << 10} {
		spec := streamChunkSpec(window)
		assert.NotPanics(t, func() { textchunk.Count(words(window*2), spec) }, "window %d", window)
	}
	assert.Equal(t, 1024, streamChunkSpec(8<<10).Overlap, "a small window shares an eighth of itself")
	assert.Equal(t, 4096, streamChunkSpec(32<<10).Overlap, "a window of 32 KiB or more holds a 3.5 KB secret whole")
	assert.Equal(t, 4096, streamChunkSpec(56<<10).Overlap)
}
