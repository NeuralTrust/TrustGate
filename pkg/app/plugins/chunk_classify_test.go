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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

func started(n int) []textchunk.Outcome[ChunkState] {
	out := make([]textchunk.Outcome[ChunkState], n)
	for i := range out {
		out[i].Started = true
	}
	return out
}

func classify(outs []textchunk.Outcome[ChunkState]) ChunkDecision {
	return ClassifyChunks(outs, false, func(_ int, v ChunkState, _ error) ChunkState { return v })
}

func fail(reason FailureReason, detail string) *ChunkFailure {
	return &ChunkFailure{Reason: reason, Detail: detail}
}

func TestClassifyChunksFollowsTheTable(t *testing.T) {
	t.Parallel()
	transport := fail(FailureTransport, "")
	throttled := fail(FailureTransport, DetailThrottled)
	notExecuted := fail(FailureVerdictIncomplete, DetailFilterNotExecuted)
	quota := fail(FailureConfigInvalid, DetailProviderQuotaExhausted)

	cases := []struct {
		name   string
		build  func() []textchunk.Outcome[ChunkState]
		kind   ChunkOutcomeKind
		index  int
		reason FailureReason
		detail string
		masked bool
	}{
		{"every chunk allowed", func() []textchunk.Outcome[ChunkState] { return started(3) }, ChunkAllowed, -1, "", "", false},
		{"the lowest blocking chunk wins over a failure", func() []textchunk.Outcome[ChunkState] {
			o := started(4)
			o[0].Value.Failure = transport
			o[2].Value.Blocks, o[3].Value.Blocks = true, true
			return o
		}, ChunkBlocked, 2, "", "", false},
		{"an input failure beats an availability one", func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[0].Value.Failure = transport
			o[2].Value.Failure = notExecuted
			return o
		}, ChunkInputFailure, 2, FailureVerdictIncomplete, DetailFilterNotExecuted, false},
		{"a chunk that never started is chunk_budget", func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[1].Started = false
			o[2].Started = false
			o[0].Value.Failure = transport
			return o
		}, ChunkInputFailure, 1, FailureInputTooLarge, DetailChunkBudget, false},
		{"a started chunk cut by the evaluation budget after waiting is chunk_budget", func() []textchunk.Outcome[ChunkState] {
			o := started(6)
			o[5].Err, o[5].Waited, o[5].BudgetCut = errors.New("context deadline exceeded"), true, true
			return o
		}, ChunkInputFailure, 5, FailureInputTooLarge, DetailChunkBudget, false},
		{"a chunk of the first round cut by the budget is the provider being slow", func() []textchunk.Outcome[ChunkState] {
			o := started(6)
			o[1].Err, o[1].BudgetCut = errors.New("context deadline exceeded"), true
			o[1].Value.Failure = transport
			return o
		}, ChunkAvailabilityFailure, 1, FailureTransport, "", false},
		{"a waiting chunk that ended on its own timeout is availability", func() []textchunk.Outcome[ChunkState] {
			o := started(6)
			o[5].Err, o[5].Waited = errors.New("client timeout"), true
			o[5].Value.Failure = transport
			return o
		}, ChunkAvailabilityFailure, 5, FailureTransport, "", false},
		{"a throttle on several chunks is input", func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[2].Value.Failure = throttled
			return o
		}, ChunkInputFailure, 2, FailureInputTooLarge, DetailThrottledOversize, false},
		{"a throttle on one chunk stays availability", func() []textchunk.Outcome[ChunkState] {
			o := started(1)
			o[0].Value.Failure = throttled
			return o
		}, ChunkAvailabilityFailure, 0, FailureTransport, DetailThrottled, false},
		{"an exhausted provider quota is configuration even on several chunks", func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[1].Value.Failure = quota
			return o
		}, ChunkAvailabilityFailure, 1, FailureConfigInvalid, DetailProviderQuotaExhausted, false},
		{"a mask is kept when another chunk fails open", func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[0].Value.Mask = true
			o[2].Value.Failure = transport
			return o
		}, ChunkAvailabilityFailure, 2, FailureTransport, "", true},
		{"a mask with no failure is reported", func() []textchunk.Outcome[ChunkState] {
			o := started(2)
			o[1].Value.Mask = true
			return o
		}, ChunkAllowed, -1, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classify(tc.build())
			assert.Equal(t, tc.kind, got.Kind)
			assert.Equal(t, tc.index, got.Index)
			assert.Equal(t, tc.reason, got.Reason)
			assert.Equal(t, tc.detail, got.Detail)
			assert.Equal(t, tc.masked, got.Masked)
		})
	}
}

func TestClassifyChunksHandsTheCallErrorToThePlugin(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	outs := []textchunk.Outcome[int]{{Value: 1, Started: true}, {Err: boom, Started: true}}
	got := ClassifyChunks(outs, false, func(_ int, _ int, err error) ChunkState {
		if err != nil {
			return ChunkState{Failure: fail(FailureTransport, "")}
		}
		return ChunkState{}
	})
	assert.Equal(t, ChunkAvailabilityFailure, got.Kind)
	assert.Equal(t, 1, got.Index)
}

func TestTheChunkDetailsAreInput(t *testing.T) {
	t.Parallel()
	for _, d := range []string{DetailChunkLimit, DetailChunkBudget, DetailThrottledOversize} {
		assert.Equal(t, FailureClassInput, ClassOf(FailureInputTooLarge, d), d)
	}
	assert.Equal(t, FailureClassAvailability, ClassOf(FailureConfigInvalid, DetailProviderQuotaExhausted))
}

// A caller whose own context ended is never an input: the content did not end
// the evaluation, a client that left did.
func TestAnEvaluationCutByTheCallersContextIsNeverInput(t *testing.T) {
	t.Parallel()
	pass := func(_ int, v ChunkState, _ error) ChunkState { return v }
	cases := map[string]struct {
		build  func() []textchunk.Outcome[ChunkState]
		kind   ChunkOutcomeKind
		reason FailureReason
		detail string
	}{
		"chunks that never ran": {func() []textchunk.Outcome[ChunkState] {
			o := started(6)
			o[4].Started, o[5].Started = false, false
			return o
		}, ChunkAvailabilityFailure, FailureTransport, ""},
		"a waiting chunk the budget cut": {func() []textchunk.Outcome[ChunkState] {
			o := started(6)
			o[5].Err, o[5].Waited, o[5].BudgetCut = errors.New("context canceled"), true, true
			o[5].Value.Failure = fail(FailureTransport, "")
			return o
		}, ChunkAvailabilityFailure, FailureTransport, ""},
		"a throttle on several chunks": {func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[1].Value.Failure = fail(FailureTransport, DetailThrottled)
			return o
		}, ChunkAvailabilityFailure, FailureTransport, DetailThrottled},
		"an input failure": {func() []textchunk.Outcome[ChunkState] {
			o := started(3)
			o[1].Value.Failure = fail(FailureVerdictIncomplete, DetailFilterNotExecuted)
			return o
		}, ChunkAvailabilityFailure, FailureTransport, ""},
		"every chunk answered": {func() []textchunk.Outcome[ChunkState] { return started(3) }, ChunkAllowed, "", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyChunks(tc.build(), true, pass)
			assert.Equal(t, tc.kind, got.Kind)
			assert.Equal(t, tc.reason, got.Reason)
			assert.Equal(t, tc.detail, got.Detail)
		})
	}

	blocking := started(3)
	blocking[1].Value.Blocks = true
	assert.Equal(t, ChunkBlocked, ClassifyChunks(blocking, true, pass).Kind, "a finding that was made still decides")
}
