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

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// A stream block whose own text is larger than the entry's window is screened
// in chunks of that window. Segmenting a block is the guard's, and the window
// is the entry's own (a provider's per-call limit), so one split here covers
// every inspector, where each plugin splitting would repeat the merge. A block
// that splits into more than maxStreamChunks is cut in a mode that blocks: the
// stream is held for the length of the call, and a client chooses the block's
// size.
const (
	maxStreamChunks       = 8
	streamChunkParallel   = 4
	maxStreamChunkOverlap = 2048
)

func streamChunkSpec(window int) textchunk.Spec {
	return textchunk.Spec{Max: window, Overlap: min(window/8, maxStreamChunkOverlap), Unit: textchunk.Bytes}
}

// inspectChunked calls inspector once per chunk of call.Accumulated and merges
// the answers into the one a single call would have given: a block of any chunk
// blocks (the lowest chunk's), a failure that is the content's is the cut, the
// masks of every chunk are mapped back onto the block (a mask that cannot be
// applied cuts, as a mask over a finding), and a failure that is availability is
// the entry's failed call unless a mask or a finding can still be used.
func (e *executor) inspectChunked(
	ctx context.Context,
	inspector StreamInspector,
	in ExecInput,
	call StreamSegment,
	entry chainEntry,
) (*SegmentVerdict, error) {
	spec := streamChunkSpec(entry.streamWindow)
	if n := textchunk.Count(call.Accumulated, spec); n > maxStreamChunks {
		return ExternalStreamOutcome(entry.plugin.Name(), entry.mode, FailureInputTooLarge, DetailChunkLimit, nil,
			fmt.Errorf("plugins: a stream block of %d bytes splits into %d chunks, above the %d screened",
				len(call.Accumulated), n, maxStreamChunks))
	}
	chunks := textchunk.Split(call.Accumulated, spec)
	blockStart := max(len(call.Accumulated)-len(call.Text), 0)

	verdicts := make([]*SegmentVerdict, len(chunks))
	outs := textchunk.Run(ctx, chunks, textchunk.RunOptions{
		Parallel: streamChunkParallel,
		StopOn:   func(i int) bool { return Blocks(entry.mode) && verdicts[i] != nil && verdicts[i].Block },
	}, func(ctx context.Context, i int, c textchunk.Chunk) (struct{}, error) {
		piece := call
		piece.Accumulated = c.Text
		piece.Text = c.Text
		if blockStart > c.Start {
			piece.Text = c.Text[min(blockStart-c.Start, len(c.Text)):]
		}
		piece.Truncated = true
		verdict, err := inspector.InspectSegment(ctx, in, piece)
		verdicts[i] = verdict
		return struct{}{}, err
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return mergeChunkVerdicts(entry, call.Accumulated, chunks, verdicts, outs)
}

func mergeChunkVerdicts(
	entry chainEntry,
	accumulated string,
	chunks []textchunk.Chunk,
	verdicts []*SegmentVerdict,
	outs []textchunk.Outcome[struct{}],
) (*SegmentVerdict, error) {
	for _, wantFinding := range []bool{true, false} {
		for i, v := range verdicts {
			if outs[i].Started && outs[i].Err == nil && v != nil && v.Block && (v.Failure == nil) == wantFinding {
				return v, nil
			}
		}
	}

	var availability error
	for _, out := range outs {
		if !out.Started || out.Err == nil {
			continue
		}
		var failure *ExternalStreamFailure
		if errors.As(out.Err, &failure) && failure.Class == FailureClassInput {
			return nil, out.Err
		}
		if availability == nil {
			availability = out.Err
		}
	}

	merged := &SegmentVerdict{}
	var fingerprints []string
	seen := map[string]struct{}{}
	masked := make([]string, len(chunks))
	anyMask := false
	for i, v := range verdicts {
		masked[i] = chunks[i].Text
		if !outs[i].Started || outs[i].Err != nil || v == nil {
			continue
		}
		for _, fp := range v.Fingerprints {
			if _, dup := seen[fp]; !dup {
				seen[fp] = struct{}{}
				fingerprints = append(fingerprints, fp)
			}
		}
		if v.Incomplete != nil && merged.Incomplete == nil {
			merged.Incomplete = v.Incomplete
		}
		if v.HasTransform {
			anyMask = true
			masked[i] = v.Transformed
		}
	}
	merged.Fingerprints = fingerprints

	if anyMask {
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
