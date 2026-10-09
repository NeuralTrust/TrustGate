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

package pluginutil

import (
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// ChunkState is what one evaluated chunk came to, as the plugin reads it: the
// provider said to block, the call failed (Failure), or it asked for a mask.
type ChunkState struct {
	Blocks  bool
	Failure *ChunkFailure
	Mask    bool
}

// ChunkFailure is a failed chunk in the shared failure vocabulary.
type ChunkFailure struct {
	Reason appplugins.FailureReason
	Detail string
}

// ChunkOutcomeKind is the verdict of a whole chunked evaluation.
type ChunkOutcomeKind int

const (
	// ChunkAllowed is every chunk answered and none blocks.
	ChunkAllowed ChunkOutcomeKind = iota
	// ChunkBlocked is a chunk that blocks. Index is the lowest one.
	ChunkBlocked
	// ChunkInputFailure is a chunk that could not be inspected because of what
	// the request carries, or that was never sent because the request's own
	// chunks used the budget.
	ChunkInputFailure
	// ChunkAvailabilityFailure is a chunk that failed for a reason the request
	// did not cause.
	ChunkAvailabilityFailure
)

// ChunkDecision is ClassifyChunks's answer. Index is the chunk the verdict or
// failure comes from. Masked is true when any chunk that answered asked for a
// mask: the caller applies the merged masks whatever the kind, because
// forwarding the original would leak what a chunk masked.
type ChunkDecision struct {
	Kind   ChunkOutcomeKind
	Index  int
	Reason appplugins.FailureReason
	Detail string
	Masked bool
}

// ChunkOptions tunes ClassifyChunks.
type ChunkOptions struct {
	// ThrottleIsInput makes a throttled chunk of an evaluation with more than
	// one chunk an input failure (throttled_oversize), for a provider that
	// meters by size and whose quota the gateway cannot see.
	ThrottleIsInput bool
}

// ClassifyChunks reads the outcomes of one chunked evaluation in a fixed order.
// A chunk that blocks wins over every failure. Then, by lowest index, a chunk
// whose failure is input; a chunk that never started because the budget ran
// out (chunk_budget); a throttle on a multi-chunk evaluation when
// ThrottleIsInput; and last a failure that is availability. Only an evaluation
// with no verdict and no failure is allowed.
func ClassifyChunks[T any](outs []textchunk.Outcome[T], o ChunkOptions,
	of func(i int, v T, err error) ChunkState,
) ChunkDecision {
	states := make([]ChunkState, len(outs))
	d := ChunkDecision{Index: -1}
	for i, out := range outs {
		if !out.Started {
			continue
		}
		states[i] = of(i, out.Value, out.Err)
		if states[i].Mask && states[i].Failure == nil && !states[i].Blocks {
			d.Masked = true
		}
	}
	for i, st := range states {
		if st.Blocks {
			d.Kind, d.Index = ChunkBlocked, i
			return d
		}
	}
	for i, st := range states {
		if st.Failure != nil && appplugins.ClassOf(st.Failure.Reason, st.Failure.Detail) == appplugins.FailureClassInput {
			return failed(d, ChunkInputFailure, i, st.Failure.Reason, st.Failure.Detail)
		}
	}
	for i, out := range outs {
		if !out.Started {
			return failed(d, ChunkInputFailure, i, appplugins.FailureInputTooLarge, appplugins.DetailChunkBudget)
		}
	}
	if o.ThrottleIsInput && len(outs) > 1 {
		for i, st := range states {
			if st.Failure != nil && st.Failure.Detail == appplugins.DetailThrottled {
				return failed(d, ChunkInputFailure, i, appplugins.FailureInputTooLarge, appplugins.DetailThrottledOversize)
			}
		}
	}
	for i, st := range states {
		if st.Failure != nil {
			return failed(d, ChunkAvailabilityFailure, i, st.Failure.Reason, st.Failure.Detail)
		}
	}
	d.Kind = ChunkAllowed
	return d
}

func failed(d ChunkDecision, kind ChunkOutcomeKind, i int, reason appplugins.FailureReason, detail string) ChunkDecision {
	d.Kind, d.Index, d.Reason, d.Detail = kind, i, reason, detail
	return d
}
