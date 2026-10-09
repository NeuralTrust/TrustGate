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

package pluginutil_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

func started(n int) []textchunk.Outcome[pluginutil.ChunkState] {
	out := make([]textchunk.Outcome[pluginutil.ChunkState], n)
	for i := range out {
		out[i].Started = true
	}
	return out
}

func classify(outs []textchunk.Outcome[pluginutil.ChunkState], o pluginutil.ChunkOptions) pluginutil.ChunkDecision {
	return pluginutil.ClassifyChunks(outs, o, func(_ int, v pluginutil.ChunkState, _ error) pluginutil.ChunkState { return v })
}

func fail(reason appplugins.FailureReason, detail string) *pluginutil.ChunkFailure {
	return &pluginutil.ChunkFailure{Reason: reason, Detail: detail}
}

func TestClassifyChunksFollowsTheTable(t *testing.T) {
	t.Parallel()
	transport := fail(appplugins.FailureTransport, "")
	throttled := fail(appplugins.FailureTransport, appplugins.DetailThrottled)
	notExecuted := fail(appplugins.FailureVerdictIncomplete, appplugins.DetailFilterNotExecuted)

	cases := []struct {
		name   string
		build  func() []textchunk.Outcome[pluginutil.ChunkState]
		opts   pluginutil.ChunkOptions
		kind   pluginutil.ChunkOutcomeKind
		index  int
		reason appplugins.FailureReason
		detail string
		masked bool
	}{
		{"every chunk allowed", func() []textchunk.Outcome[pluginutil.ChunkState] { return started(3) }, pluginutil.ChunkOptions{}, pluginutil.ChunkAllowed, -1, "", "", false},
		{"the lowest blocking chunk wins over a failure", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(4)
			o[0].Value.Failure = transport
			o[2].Value.Blocks, o[3].Value.Blocks = true, true
			return o
		}, pluginutil.ChunkOptions{}, pluginutil.ChunkBlocked, 2, "", "", false},
		{"an input failure beats an availability one", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(3)
			o[0].Value.Failure = transport
			o[2].Value.Failure = notExecuted
			return o
		}, pluginutil.ChunkOptions{}, pluginutil.ChunkInputFailure, 2, appplugins.FailureVerdictIncomplete, appplugins.DetailFilterNotExecuted, false},
		{"a chunk that never started is chunk_budget", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(3)
			o[1].Started = false
			o[2].Started = false
			o[0].Value.Failure = transport
			return o
		}, pluginutil.ChunkOptions{}, pluginutil.ChunkInputFailure, 1, appplugins.FailureInputTooLarge, appplugins.DetailChunkBudget, false},
		{"a throttle on several chunks is input when asked", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(3)
			o[2].Value.Failure = throttled
			return o
		}, pluginutil.ChunkOptions{ThrottleIsInput: true}, pluginutil.ChunkInputFailure, 2, appplugins.FailureInputTooLarge, appplugins.DetailThrottledOversize, false},
		{"a throttle on one chunk stays availability", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(1)
			o[0].Value.Failure = throttled
			return o
		}, pluginutil.ChunkOptions{ThrottleIsInput: true}, pluginutil.ChunkAvailabilityFailure, 0, appplugins.FailureTransport, appplugins.DetailThrottled, false},
		{"a throttle is availability unless asked", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(3)
			o[1].Value.Failure = throttled
			return o
		}, pluginutil.ChunkOptions{}, pluginutil.ChunkAvailabilityFailure, 1, appplugins.FailureTransport, appplugins.DetailThrottled, false},
		{"a mask is kept when another chunk fails open", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(3)
			o[0].Value.Mask = true
			o[2].Value.Failure = transport
			return o
		}, pluginutil.ChunkOptions{}, pluginutil.ChunkAvailabilityFailure, 2, appplugins.FailureTransport, "", true},
		{"a mask with no failure is reported", func() []textchunk.Outcome[pluginutil.ChunkState] {
			o := started(2)
			o[1].Value.Mask = true
			return o
		}, pluginutil.ChunkOptions{}, pluginutil.ChunkAllowed, -1, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classify(tc.build(), tc.opts)
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
	got := pluginutil.ClassifyChunks(outs, pluginutil.ChunkOptions{}, func(_ int, _ int, err error) pluginutil.ChunkState {
		if err != nil {
			return pluginutil.ChunkState{Failure: fail(appplugins.FailureTransport, "")}
		}
		return pluginutil.ChunkState{}
	})
	assert.Equal(t, pluginutil.ChunkAvailabilityFailure, got.Kind)
	assert.Equal(t, 1, got.Index)
}

func TestTheChunkDetailsAreInput(t *testing.T) {
	t.Parallel()
	for _, d := range []string{appplugins.DetailChunkLimit, appplugins.DetailChunkBudget, appplugins.DetailThrottledOversize} {
		assert.Equal(t, appplugins.FailureClassInput, appplugins.ClassOf(appplugins.FailureInputTooLarge, d), d)
	}
}
