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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// A provider whose quota admits only the first piece to arrive throttles pieces
// that are the block's own siblings. Piece 0 is sent alone, so it is the first
// to arrive and is never the one throttled: the throttle lands on a later piece
// and is the block's size (input), whichever order the goroutines would have
// reached the provider in.
func TestRunStreamSegment_AQuotaThatAdmitsTheFirstArrivalNeverThrottlesPieceZero(t *testing.T) {
	t.Parallel()
	text := words(40000)
	var failedOpen atomic.Int32
	for n := range 60 {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			var arrivals atomic.Int32
			exec, in, _ := chunkChain(t, policy.ModeEnforce, 8192, func(StreamSegment) (*SegmentVerdict, error) {
				if arrivals.Add(1) > 1 {
					return nil, newExternalStreamFailure("guard", FailureTransport, DetailThrottled, errors.New("429"))
				}
				return &SegmentVerdict{}, nil
			})

			out, err := exec.RunStreamSegment(context.Background(), in, StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})

			if err != nil || !out.Block {
				failedOpen.Add(1)
			}
		})
	}
	t.Cleanup(func() { assert.Zero(t, failedOpen.Load(), "runs of 60 that failed open") })
}

// hangingGuard hangs every piece until its own call timeout, at the default
// parallelism, as the plugins' stream inspectors bound their calls.
type hangingGuard struct {
	*chunkGuard
	calls   atomic.Int32
	timeout time.Duration
}

func (g *hangingGuard) InspectSegment(ctx context.Context, _ ExecInput, seg StreamSegment) (*SegmentVerdict, error) {
	if seg.Closing {
		return nil, nil
	}
	g.calls.Add(1)
	callCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	<-callCtx.Done()
	return nil, callCtx.Err()
}

func (g *hangingGuard) StreamGuardTimeout() time.Duration { return g.timeout }

// A provider that hangs is found on piece 0, which is sent alone: no other piece
// starts after its call timed out, and the block fails open after about one piece
// timeout however many rounds it has.
func TestRunStreamSegment_AHangStopsTheBlockAfterTheFirstPieceTimesOut(t *testing.T) {
	t.Parallel()
	g := &hangingGuard{
		chunkGuard: &chunkGuard{fakePlugin: fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{StatusCode: 200}}},
		timeout:    400 * time.Millisecond,
	}
	pol := policies(t, polSpec{slug: "guard", enabled: true, priority: 10, stages: []policy.Stage{policy.StagePreResponse}})[0]
	pol.Mode = policy.ModeEnforce
	pol.Settings = map[string]any{"enabled": true, "max_accumulated_bytes": 8192}
	exec, ok := NewExecutor(newRegistry(t, g), nil).(*executor)
	require.True(t, ok)
	text := words(40000)

	started := time.Now()
	out, err := exec.RunStreamSegment(context.Background(), failureInput([]*policy.Policy{pol}), StreamSegment{StreamID: "s", Seq: 1, Text: text, Accumulated: text})
	took := time.Since(started)

	require.NoError(t, err)
	assert.False(t, out.Block, "a hang is availability")
	assert.Less(t, took, g.timeout*3/2)
	assert.EqualValues(t, 1, g.calls.Load(), "no piece starts after the first timed out")
}
