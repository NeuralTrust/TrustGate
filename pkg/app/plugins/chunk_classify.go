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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// ChunkState is what one chunk of an evaluation came to, as the plugin reads
// it: the provider said to block, the call failed (Failure), or it asked for a
// mask. Started is false for a chunk that was never sent.
type ChunkState struct {
	Started bool
	// Waited says the chunk was dispatched after the first round, queued behind
	// chunks of the same evaluation (ClassifyChunks fills it from the outcome).
	Waited  bool
	Blocks  bool
	Failure *ChunkFailure
	Mask    bool
}

// ChunkFailure is a failed chunk in the shared failure vocabulary.
type ChunkFailure struct {
	Reason FailureReason
	Detail string
	// OtherTraffic says the request's own calls cannot have caused a throttle
	// (they are spaced under the provider's documented quota), so it stays
	// availability on an evaluation of several chunks.
	OtherTraffic bool
}

// ChunkOutcomeKind is the verdict of a whole chunked evaluation.
type ChunkOutcomeKind int

const (
	// ChunkAllowed is every chunk answered and none blocks.
	ChunkAllowed ChunkOutcomeKind = iota
	// ChunkBlocked is a chunk that blocks. Index is the lowest one.
	ChunkBlocked
	// ChunkInputFailure is a chunk that could not be inspected because of what
	// the request carries, or that the request's own size kept from being
	// inspected (never sent, cut by the evaluation's budget, throttled).
	ChunkInputFailure
	// ChunkAvailabilityFailure is a chunk that failed for a reason the request
	// did not cause.
	ChunkAvailabilityFailure
)

// ChunkDecision is the answer of DecideChunks. Index is the chunk the verdict
// or failure comes from. Masked is true when any chunk that answered asked for
// a mask: the caller applies the merged masks whatever the kind, because
// forwarding the original would leak what a chunk masked.
type ChunkDecision struct {
	Kind   ChunkOutcomeKind
	Index  int
	Reason FailureReason
	Detail string
	Masked bool
}

// ClassifyOption changes how ClassifyChunks reads a time cut.
type ClassifyOption func(*classifyConfig)

type classifyConfig struct{ slow time.Duration }

// SlowCall sets how long a started chunk's call has to take to count as the
// provider being slow (textchunk.SlowCall). Without it no call counts as slow,
// and a time cut is always the request's own size.
func SlowCall(d time.Duration) ClassifyOption {
	return func(c *classifyConfig) { c.slow = d }
}

// ClassifyChunks reads the outcomes of one chunked evaluation through the one
// precedence table every guardrail shares (DecideChunks), after applying the
// one rule for a time cut: a chunk that was never started, or that waited behind
// the request's own chunks and was cut by the evaluation's budget, is
// availability only when a started chunk's call took longer than the SlowCall
// threshold (the provider was slow, and its time ran the budget out), and is
// chunk_budget, input, otherwise (the request's own size used the budget while
// every call answered at its usual pace). of maps every other started chunk.
//
// cancelled is the client having left (the caller's context was cancelled), which
// the caller reads as errors.Is(ctx.Err(), context.Canceled). Nothing in the
// content ended the evaluation then, so none of the input readings apply: a chunk
// that blocks still decides, and otherwise the evaluation is an availability
// failure, the first failed chunk's or, with none, a bare transport failure for
// the chunks that never ran. A parent deadline is not a cancellation: it follows
// the budget rule above.
func ClassifyChunks[T any](
	outs []textchunk.Outcome[T], cancelled bool, of func(i int, v T, err error) ChunkState, opts ...ClassifyOption,
) ChunkDecision {
	var cfg classifyConfig
	for _, o := range opts {
		o(&cfg)
	}
	slow := false
	for _, out := range outs {
		if out.Started && cfg.slow > 0 && out.Took > cfg.slow {
			slow = true
		}
	}
	states := make([]ChunkState, len(outs))
	for i, out := range outs {
		if !out.Started {
			if slow {
				states[i] = ChunkState{Started: true, Failure: &ChunkFailure{Reason: FailureTransport}}
			}
			continue
		}
		if out.Err != nil && out.BudgetCut && out.Waited && !cancelled && !slow {
			states[i] = ChunkState{Started: true, Waited: true, Failure: &ChunkFailure{Reason: FailureInputTooLarge, Detail: DetailChunkBudget}}
			continue
		}
		states[i] = of(i, out.Value, out.Err)
		states[i].Started = true
		states[i].Waited = out.Waited
	}
	return DecideChunks(states, cancelled)
}

// DecideChunks is the precedence of a chunked evaluation (see ClassifyChunks for
// cancelled), shared by the buffered legs and the stream leg. A chunk that blocks wins over every
// failure. Then, by lowest index: a failure that is the content's (input);
// a chunk that never started because the budget ran out (chunk_budget); a
// throttle on an evaluation of more than one chunk (throttled_oversize), since
// a request split into several calls is large next to the provider's per-call
// limit and plausibly part of the quota that throttled it; and last a failure
// that is availability. An evaluation with no verdict and no failure is
// allowed.
//
// A throttle on a chunk of the first round stays availability: nothing of the
// request's own was in flight before it, so other traffic caused it. So does a
// provider quota that is configuration (an exhausted or unbilled account): those are
// recorded as config_invalid and never carry the throttled detail.
func DecideChunks(states []ChunkState, cancelled bool) ChunkDecision {
	d := ChunkDecision{Index: -1}
	for _, st := range states {
		if st.Started && st.Mask && st.Failure == nil && !st.Blocks {
			d.Masked = true
		}
	}
	for i, st := range states {
		if st.Started && st.Blocks {
			d.Kind, d.Index = ChunkBlocked, i
			return d
		}
	}
	if cancelled {
		return cancelledChunks(d, states)
	}
	for i, st := range states {
		if st.Started && st.Failure != nil && ClassOf(st.Failure.Reason, st.Failure.Detail) == FailureClassInput {
			return failedChunk(d, ChunkInputFailure, i, st.Failure.Reason, st.Failure.Detail)
		}
	}
	for i, st := range states {
		if !st.Started {
			return failedChunk(d, ChunkInputFailure, i, FailureInputTooLarge, DetailChunkBudget)
		}
	}
	for i, st := range states {
		if st.Started && st.Waited && st.Failure != nil && st.Failure.Detail == DetailThrottled && !st.Failure.OtherTraffic {
			return failedChunk(d, ChunkInputFailure, i, FailureInputTooLarge, DetailThrottledOversize)
		}
	}
	for i, st := range states {
		if st.Failure != nil {
			return failedChunk(d, ChunkAvailabilityFailure, i, st.Failure.Reason, st.Failure.Detail)
		}
	}
	d.Kind = ChunkAllowed
	return d
}

// cancelledChunks is DecideChunks for an evaluation the caller's own context
// cut short, after a blocking chunk has been ruled out. It is never input.
func cancelledChunks(d ChunkDecision, states []ChunkState) ChunkDecision {
	for i, st := range states {
		if st.Failure != nil && ClassOf(st.Failure.Reason, st.Failure.Detail) == FailureClassAvailability {
			return failedChunk(d, ChunkAvailabilityFailure, i, st.Failure.Reason, st.Failure.Detail)
		}
	}
	for i, st := range states {
		if !st.Started || st.Failure != nil {
			return failedChunk(d, ChunkAvailabilityFailure, i, FailureTransport, "")
		}
	}
	d.Kind = ChunkAllowed
	return d
}

func failedChunk(d ChunkDecision, kind ChunkOutcomeKind, i int, reason FailureReason, detail string) ChunkDecision {
	d.Kind, d.Index, d.Reason, d.Detail = kind, i, reason, detail
	return d
}
