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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// A stream block whose own text is larger than the entry's window is screened
// in chunks of that window. Segmenting a block is the guard's, and the window
// is the entry's own (a provider's per-call limit), so one split here covers
// every inspector, where each plugin splitting would repeat the merge. A block
// that splits into more than maxStreamChunks is cut in a mode that blocks: the
// stream is held for the length of the call, and a client chooses the block's
// size.
//
// An inspector that bounds its own payload (StreamPayloadBound) is not split:
// it is sent the block whole, as one call, because it is one evaluation of the
// whole block that it answers for.
const (
	maxStreamChunks        = 8
	streamChunkParallel    = 4
	streamChunkOverlap     = 4096
	streamChunkOverlapFrom = 32 << 10

	defaultStreamPieceTimeout = 2 * time.Second
	// maxBlockTimeouts caps a block's deadline at this many piece timeouts, so
	// a stream is held for a bounded time however many pieces a block has and
	// however slow they are.
	maxBlockTimeouts = 4
)

// StreamPayloadBound is the optional declaration of a StreamInspector that
// bounds the payload it sends itself, and must therefore be handed a block
// whole: the executor never splits a block for it. Splitting would repeat its
// per-call state (the position of a block in the stream, the block that ends
// the response) once per piece.
type StreamPayloadBound interface {
	BoundsStreamPayload() bool
}

// StreamChunkParallelism is the optional declaration of a StreamInspector that
// cannot take the executor's default number of calls at once, because its
// provider meters calls it cannot tell apart (a quota on units a second): the
// pieces of a block are sent that many at a time. An inspector that does not
// declare it is sent streamChunkParallel pieces at once.
type StreamChunkParallelism interface {
	StreamChunkParallel() int
}

func chunkParallelOf(inspector StreamInspector) int {
	if p, ok := inspector.(StreamChunkParallelism); ok && p.StreamChunkParallel() >= 1 {
		return p.StreamChunkParallel()
	}
	return streamChunkParallel
}

// StreamPieceSpacing is the optional declaration of a StreamInspector whose
// provider meters text by a quota a second: SpaceStreamPieces returns the wait
// that runs before each piece of one block, given the piece's size in bytes,
// which spaces the pieces under that quota. It is called once per block, so the
// spacing is local to the block and shares no state between blocks. It may
// return nil for no spacing.
type StreamPieceSpacing interface {
	SpaceStreamPieces(in ExecInput) func(ctx context.Context, bytes int) error
}

// StreamThrottleAttribution is the optional declaration of a StreamInspector
// whose pieces are spaced under its provider's quota (StreamPieceSpacing), so a
// throttle on a piece cannot be the block's own doing: it is other traffic, and
// availability whichever piece it is on.
type StreamThrottleAttribution interface {
	StreamThrottleIsOtherTraffic() bool
}

// StreamPieceTimeout is the optional declaration of the time one piece's call
// may take, which the block's deadline is made of. An inspector that does not
// declare it is given defaultStreamPieceTimeout.
type StreamPieceTimeout interface {
	StreamGuardTimeout() time.Duration
}

func pieceTimeoutOf(inspector StreamInspector) time.Duration {
	if t, ok := inspector.(StreamPieceTimeout); ok && t.StreamGuardTimeout() > 0 {
		return t.StreamGuardTimeout()
	}
	return defaultStreamPieceTimeout
}

func throttleIsOtherTraffic(plugin Plugin) bool {
	a, ok := plugin.(StreamThrottleAttribution)
	return ok && a.StreamThrottleIsOtherTraffic()
}

func boundsOwnPayload(inspector StreamInspector) bool {
	b, ok := inspector.(StreamPayloadBound)
	return ok && b.BoundsStreamPayload()
}

// streamChunkSpec is how a block is cut for a window. A window of 32 KiB or more
// shares 4,096 bytes between neighbours, so a long secret (a PEM key, a
// service-account JSON of about 3.5 KB) lies whole in one chunk; a smaller
// window cannot spare that much and shares an eighth of itself. The residual is
// a pattern longer than the overlap, or a context that a cut separates by more
// than it.
func streamChunkSpec(window int) textchunk.Spec {
	overlap := window / 8
	if window >= streamChunkOverlapFrom {
		overlap = streamChunkOverlap
	}
	return textchunk.Spec{Max: window, Overlap: min(overlap, textchunk.MaxOverlap(window)), Unit: textchunk.Bytes}
}

// inspectChunked calls inspector once per chunk of call.Accumulated and merges
// the answers into the one a single call would have given (mergeChunkVerdicts).
// onChunked is called once the block is known to be within maxStreamChunks, so
// a block refused for its size is not counted as screened.
//
// The block is bounded by a deadline of one piece timeout per round of pieces, at
// most maxBlockTimeouts of them, so a stream is held for a bounded time whatever
// the provider does. A piece that was not started or was cut by that deadline is
// read by the one rule of ClassifyChunks: availability only when some piece's call
// took more than half of its timeout, otherwise chunk_budget, input. An inspector
// that spaces its pieces (StreamPieceSpacing) has the spacing wait run before each
// piece, outside the time the call is measured by.
//
// A piece of the first round that is throttled is sent once more after a short
// backoff, as the buffered legs do, unless the inspector says its pieces are
// spaced under its quota (StreamThrottleAttribution): a throttle there is other
// traffic and a retry would only add to it.
//
// Only the chunk that reaches the end of call.Accumulated carries Final, and
// every piece shares the block's Seq and says which it is (Part of Parts), so an
// inspector that keys on the block position sees it once per piece and the end
// of the response once.
func (e *executor) inspectChunked(
	ctx context.Context,
	inspector StreamInspector,
	in ExecInput,
	call StreamSegment,
	entry chainEntry,
	onChunked func(),
) (*SegmentVerdict, error) {
	spec := streamChunkSpec(entry.streamWindow)
	if n := textchunk.Count(call.Accumulated, spec); n > maxStreamChunks {
		return ExternalStreamOutcome(entry.plugin.Name(), entry.mode, FailureInputTooLarge, DetailChunkLimit, nil,
			fmt.Errorf("plugins: a stream block of %d bytes splits into %d chunks, above the %d screened",
				len(call.Accumulated), n, maxStreamChunks))
	}
	onChunked()
	chunks := textchunk.Split(call.Accumulated, spec)
	blockStart := max(len(call.Accumulated)-len(call.Text), 0)

	parallel := chunkParallelOf(inspector)
	timeout := pieceTimeoutOf(inspector)
	blockCtx, cancel := context.WithTimeout(ctx, min(timeout*time.Duration(textchunk.Rounds(len(chunks), parallel)), maxBlockTimeouts*timeout))
	defer cancel()
	reserve := timeout / 4
	slow := textchunk.SlowCallOf(blockCtx, reserve)
	var space func(ctx context.Context, bytes int) error
	if s, ok := inspector.(StreamPieceSpacing); ok {
		space = s.SpaceStreamPieces(in)
	}

	retryable := !throttleIsOtherTraffic(entry.plugin)
	verdicts := make([]*SegmentVerdict, len(chunks))
	outs := textchunk.Run(blockCtx, chunks, textchunk.RunOptions{
		Parallel: parallel,
		Reserve:  reserve,
		StopOn:   func(i int) bool { return Blocks(entry.mode) && verdicts[i] != nil && verdicts[i].Block },
		Before: func(ctx context.Context, _ int, c textchunk.Chunk) error {
			if space == nil {
				return nil
			}
			return space(ctx, len(c.Text))
		},
	}, func(ctx context.Context, i int, c textchunk.Chunk) (struct{}, error) {
		piece := call
		piece.Accumulated = c.Text
		piece.Text = c.Text
		if blockStart > c.Start {
			piece.Text = c.Text[min(blockStart-c.Start, len(c.Text)):]
		}
		piece.Truncated = true
		piece.Final = call.Final && c.End == len(call.Accumulated)
		piece.Part, piece.Parts = i+1, len(chunks)
		verdict, err := inspector.InspectSegment(ctx, in, piece)
		if retryable && i < parallel && pieceThrottled(verdict, err) {
			if textchunk.Pause(ctx, pieceRetryWait(ctx)) {
				verdict, err = inspector.InspectSegment(ctx, in, piece)
			}
		}
		verdicts[i] = verdict
		return struct{}{}, err
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return mergeChunkVerdicts(entry, call.Accumulated, chunks, verdicts, outs, SlowCall(slow))
}

// pieceRetryBackoff is the wait before a throttled piece is sent again.
const pieceRetryBackoff = 250 * time.Millisecond

// pieceThrottled reports that a piece's call ended on a throttle, whether the
// inspector returned it as the error or as a blocking verdict that carries it.
func pieceThrottled(v *SegmentVerdict, err error) bool {
	if err != nil {
		var typed *ExternalStreamFailure
		return errors.As(err, &typed) && typed.Detail == DetailThrottled
	}
	return v != nil && v.Block && v.Failure != nil && v.Failure.Detail == DetailThrottled
}

// pieceRetryWait is the backoff before a piece is retried: never more than a
// quarter of the time the block has left or than the run's reserve.
func pieceRetryWait(ctx context.Context) time.Duration {
	wait := pieceRetryBackoff
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)/4)
	}
	if limit := textchunk.PauseCap(ctx); limit > 0 {
		wait = min(wait, limit)
	}
	return max(wait, 0)
}

// mergeChunkVerdicts reads the chunks through the same precedence table the
// buffered legs use (ClassifyChunks), so one provider answer means the same
// thing on either leg:
//
//   - a block of any chunk blocks, and a block that is a finding wins over one
//     that is a failure (the lowest chunk's, as a copy);
//   - a failure that is the content's, or the request's own size (a chunk that
//     never ran or was cut by the block's deadline with no slow call, a throttle
//     the block's own pieces caused), is the cut, or in a mode that does not
//     block the typed error as it came; a throttle is the block's own doing when it
//     is on a piece other than the first, unless the inspector says its pieces are
//     spaced (StreamThrottleAttribution), which makes it other traffic;
//   - the masks of every chunk are mapped back onto the block, and a mask that
//     cannot be applied cuts, as a mask over a finding;
//   - a failure that is availability is the entry's failed call unless a mask or
//     a finding can still be used.
//
// A mode that does not block and has findings to keep reports them with the
// failure: a typed error returned as it came would drop the fingerprints of the
// chunks that answered.
//
// Whatever the outcome, the fingerprints of every chunk that answered are
// carried, and so is the first Incomplete among them, so an observe entry keeps
// every chunk's findings.
func mergeChunkVerdicts(
	entry chainEntry,
	accumulated string,
	chunks []textchunk.Chunk,
	verdicts []*SegmentVerdict,
	outs []textchunk.Outcome[struct{}],
	opts ...ClassifyOption,
) (*SegmentVerdict, error) {
	otherTraffic := throttleIsOtherTraffic(entry.plugin)
	d := ClassifyChunks(outs, false, func(i int, _ struct{}, err error) ChunkState {
		if err != nil {
			reason, detail := streamFailureOf(err)
			return ChunkState{Failure: &ChunkFailure{Reason: reason, Detail: detail, OtherTraffic: otherTraffic && detail == DetailThrottled}}
		}
		switch v := verdicts[i]; {
		case v == nil:
		case v.Block && v.Failure == nil:
			return ChunkState{Blocks: true}
		case v.Block:
			return ChunkState{Failure: &ChunkFailure{Reason: v.Failure.Reason, Detail: v.Failure.Detail, OtherTraffic: otherTraffic && v.Failure.Detail == DetailThrottled}}
		case v.HasTransform:
			return ChunkState{Mask: true}
		}
		return ChunkState{}
	}, opts...)

	var fingerprints []string
	seen := map[string]struct{}{}
	var incomplete error
	for i, v := range verdicts {
		if !outs[i].Started || outs[i].Err != nil || v == nil {
			continue
		}
		for _, fp := range v.Fingerprints {
			if _, dup := seen[fp]; !dup {
				seen[fp] = struct{}{}
				fingerprints = append(fingerprints, fp)
			}
		}
		if v.Incomplete != nil && incomplete == nil {
			incomplete = v.Incomplete
		}
	}
	carry := func(v SegmentVerdict) *SegmentVerdict {
		v.Fingerprints = fingerprints
		if v.Incomplete == nil {
			v.Incomplete = incomplete
		}
		return &v
	}

	switch d.Kind {
	case ChunkBlocked:
		return carry(*verdicts[d.Index]), nil
	case ChunkInputFailure:
		if v := verdicts[d.Index]; outs[d.Index].Started && outs[d.Index].Err == nil && v != nil && v.Block {
			return carry(*v), nil
		}
		keepsFindings := !Blocks(entry.mode) && len(fingerprints) > 0
		var typed *ExternalStreamFailure
		if err := outs[d.Index].Err; !keepsFindings && err != nil && errors.As(err, &typed) && typed.Reason == d.Reason && typed.Detail == d.Detail {
			return nil, err
		}
		var block *SegmentVerdict
		if keepsFindings {
			block = &SegmentVerdict{Fingerprints: fingerprints}
		}
		return ExternalStreamOutcome(entry.plugin.Name(), entry.mode, d.Reason, d.Detail, block, chunkFailureError(d, outs, len(chunks)))
	}

	var availability error
	if d.Kind == ChunkAvailabilityFailure {
		availability = outs[d.Index].Err
		if availability == nil {
			availability = chunkFailureError(d, outs, len(chunks))
		}
	}
	merged := carry(SegmentVerdict{})
	if d.Masked {
		masked := make([]string, len(chunks))
		for i, c := range chunks {
			masked[i] = c.Text
			if outs[i].Started && outs[i].Err == nil && verdicts[i] != nil && verdicts[i].HasTransform {
				masked[i] = verdicts[i].Transformed
			}
		}
		text, ok := textchunk.MergeMasks(accumulated, chunks, masked)
		if !ok {
			return ExternalStreamOutcome(entry.plugin.Name(), entry.mode, FailureVerdictIncomplete, DetailAnonymizeEncodeFailed, nil,
				errors.New("plugins: the masks of a chunked stream block cannot be mapped back onto it"))
		}
		merged.HasTransform, merged.Transformed = true, text
		if availability != nil && merged.Incomplete == nil {
			merged.Incomplete = availability
		}
		return merged, nil
	}
	if availability != nil {
		if len(fingerprints) > 0 {
			merged.Incomplete = availability
			return merged, nil
		}
		return nil, availability
	}
	return merged, nil
}

// streamFailureOf is the reason and detail a chunk's error carries: the typed
// failure a plugin returned, else a bare transport failure.
func streamFailureOf(err error) (FailureReason, string) {
	var typed *ExternalStreamFailure
	if errors.As(err, &typed) {
		return typed.Reason, typed.Detail
	}
	return FailureTransport, ""
}

func chunkFailureError(d ChunkDecision, outs []textchunk.Outcome[struct{}], count int) error {
	if d.Index >= 0 && d.Index < len(outs) && outs[d.Index].Err != nil {
		return fmt.Errorf("plugins: chunk %d of %d of a stream block: %w", d.Index+1, count, outs[d.Index].Err)
	}
	return fmt.Errorf("plugins: chunk %d of %d of a stream block was not screened (%s)", d.Index+1, count, d.Detail)
}
