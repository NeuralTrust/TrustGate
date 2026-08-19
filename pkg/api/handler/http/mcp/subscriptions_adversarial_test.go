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

package mcp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/stretchr/testify/require"
)

const (
	// goroutineTolerance matches pkg/infra/providers/stream_test.go: the runtime's
	// own bookkeeping goroutines come and go independently of the code under test.
	goroutineTolerance = 2

	// concurrentStreams is the N the memory thresholds are stated for.
	concurrentStreams = 64

	// memoryCeilingPerStream is threshold A: retained bytes per live stream.
	memoryCeilingPerStream = 64 << 10

	// memoryDriftPerStream is threshold B, the sharp one: how much a stream may
	// grow between tick 5 and tick 20. Anything retained per frame fails it long
	// before it reaches the ceiling.
	memoryDriftPerStream = 4 << 10

	driftFirstTick  = 5
	driftSecondTick = 20
)

func goroutineBaseline() int {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	return runtime.NumGoroutine()
}

func goroutineCount() int {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	return runtime.NumGoroutine()
}

// retainedHeap is what the memory thresholds are measured in. Two collections
// are what the design specifies: the first frees the garbage, the second finishes
// the sweep the first started, so what is left is genuinely retained.
func retainedHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapInuse
}

// Every termination path ends the lease's one goroutine. The paths are driven
// through the same loop the handler runs, so a path that parked a goroutine on a
// timer or a channel would show up as a count that never comes back down.
func TestRunSubscriptionStreamLeavesNoGoroutineOnAnyTerminationPath(t *testing.T) {
	const leases = 24

	tests := []struct {
		name  string
		sink  func() *recordingSink
		spec  func(subscriptionTimers) streamSpec
		drive func(context.CancelFunc, *fakeTimers)
		want  subscriptionOutcome
	}{
		{
			name:  "the client disconnects",
			sink:  func() *recordingSink { return &recordingSink{commentErr: errors.New("broken pipe")} },
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.keepalive <- time.Now() },
			want:  subscriptionOutcomeDisconnected,
		},
		{
			name:  "the lease deadline fires",
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.deadline <- time.Now() },
			want:  subscriptionOutcomeDeadline,
		},
		{
			name:  "the process drains for shutdown",
			drive: func(cancel context.CancelFunc, _ *fakeTimers) { cancel() },
			want:  subscriptionOutcomeShutdown,
		},
		{
			name:  "a frame breaches the size bound",
			sink:  func() *recordingSink { return &recordingSink{commentErr: ErrFrameTooLarge} },
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.keepalive <- time.Now() },
			want:  subscriptionOutcomeOversize,
		},
		{
			name: "authorization is refused",
			spec: func(timers subscriptionTimers) streamSpec {
				return testReauthSpec(&scriptedPolicy{err: appmcp.ErrSubscriptionRevoked}, timers)
			},
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.reauth <- time.Now() },
			want:  subscriptionOutcomeRevoked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseline := goroutineBaseline()

			for range leases {
				ctx, cancel := context.WithCancel(context.Background())
				sink := frameSink(&recordingSink{})
				if tc.sink != nil {
					sink = tc.sink()
				}
				timers, fake := newFakeTimers()
				spec := testStreamSpec(honouredKinds(), timers)
				if tc.spec != nil {
					spec = tc.spec(timers)
				}

				done := startLoop(ctx, sink, spec)
				tc.drive(cancel, fake)
				require.Equal(t, tc.want, awaitOutcome(t, done))
				<-fake.stopped
				cancel()
			}

			require.LessOrEqual(t, goroutineCount(), baseline+goroutineTolerance,
				"the lease's goroutine outlived the stream")
		})
	}
}

// A lease is exactly one goroutine while it is live, and the count returns to
// where it started once capacity is reclaimed.
func TestRunSubscriptionStreamCostsOneGoroutinePerLiveStream(t *testing.T) {
	baseline := goroutineBaseline()

	fakes := make([]*fakeTimers, 0, concurrentStreams)
	outcomes := make([]<-chan subscriptionOutcome, 0, concurrentStreams)
	for range concurrentStreams {
		timers, fake := newFakeTimers()
		fakes = append(fakes, fake)
		outcomes = append(outcomes, startLoop(
			context.Background(),
			&recordingSink{},
			testStreamSpec(honouredKinds(), timers),
		))
	}

	live := goroutineCount()
	require.GreaterOrEqual(t, live, baseline+concurrentStreams-goroutineTolerance)
	require.LessOrEqual(t, live, baseline+concurrentStreams+goroutineTolerance,
		"a live stream costs more than the one goroutine it is allowed")

	for _, fake := range fakes {
		fake.deadline <- time.Now()
	}
	for _, done := range outcomes {
		require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))
	}

	require.LessOrEqual(t, goroutineCount(), baseline+goroutineTolerance)
}

// Threshold A bounds what a live stream retains; threshold B bounds what it
// accumulates while it runs. B is the sharp one: a per-frame allocation the loop
// holds on to shows up between tick 5 and tick 20 long before it reaches the
// ceiling.
func TestRunSubscriptionStreamRetainsBoundedMemoryPerStream(t *testing.T) {
	tests := []struct {
		name   string
		writer func() (io.Writer, func())
	}{
		{
			name: "a client that reads",
			writer: func() (io.Writer, func()) {
				return io.Discard, func() {}
			},
		},
		{
			// A peer that never drains its socket parks the stream inside Flush
			// on a fixed-size buffer, so the credit granted per tick is the only
			// thing that lets it advance at all.
			name: "a client that never reads",
			writer: func() (io.Writer, func()) {
				w := newCreditedWriter()
				return w, w.grant
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseline := retainedHeap()

			fakes := make([]*fakeTimers, 0, concurrentStreams)
			grants := make([]func(), 0, concurrentStreams)
			outcomes := make([]<-chan subscriptionOutcome, 0, concurrentStreams)
			for range concurrentStreams {
				timers, fake := newFakeTimers()
				writer, grant := tc.writer()
				fakes = append(fakes, fake)
				grants = append(grants, grant)
				spec := testReauthSpec(&scriptedPolicy{passes: alternatingSurfaces()}, timers)
				outcomes = append(outcomes, startLoop(
					context.Background(),
					newBufioSink(bufio.NewWriter(writer), defaultSubscriptionMaxEventBytes),
					spec,
				))
			}
			grantAll := func(times int) {
				for range times {
					for _, grant := range grants {
						grant()
					}
				}
			}

			var atFirst uint64
			for tick := 1; tick <= driftSecondTick; tick++ {
				grantAll(1)
				for _, fake := range fakes {
					fake.reauth <- time.Now()
				}
				if tick == driftFirstTick {
					atFirst = retainedHeap()
				}
			}
			atSecond := retainedHeap()

			grantAll(2)
			for _, fake := range fakes {
				fake.deadline <- time.Now()
			}
			for _, done := range outcomes {
				require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))
			}

			require.LessOrEqual(t, perStream(atFirst, baseline), uint64(memoryCeilingPerStream),
				"a live stream retains more than the ceiling allows")
			require.LessOrEqual(t, perStream(atSecond, atFirst), uint64(memoryDriftPerStream),
				"a stream grew between tick 5 and tick 20, so something is retained per frame")
		})
	}
}

// perStream is the measured quantity: the growth over a reference point, divided
// across the streams that caused it. A reading below the reference is reported as
// zero rather than wrapping.
func perStream(measured, reference uint64) uint64 {
	if measured <= reference {
		return 0
	}
	return (measured - reference) / concurrentStreams
}

// alternatingSurfaces makes every tick a real emission: the digest moves on each
// pass, so each tick renders and writes a notification frame.
func alternatingSurfaces() []scriptedPass {
	passes := make([]scriptedPass, 0, driftSecondTick+1)
	for i := 0; i <= driftSecondTick; i++ {
		digest := "aaaaaaaaaaaa"
		if i%2 == 1 {
			digest = "bbbbbbbbbbbb"
		}
		passes = append(passes, scriptedPass{
			changed:  []appmcp.NotificationKind{appmcp.NotificationToolsListChanged},
			snapshot: appmcp.SurfaceSnapshot{Tools: digest},
		})
	}
	return passes
}

// creditedWriter models a socket the peer is not draining: a write blocks until
// the test grants it credit, which is what puts the stream under back-pressure
// without a sleep. One writer belongs to one stream, so a stream can only ever be
// released by its own grant. The bytes themselves are dropped, because what is
// being measured is what the writer holds on to, not what it sent.
type creditedWriter struct {
	credit chan struct{}
}

func newCreditedWriter() *creditedWriter {
	return &creditedWriter{credit: make(chan struct{}, 4)}
}

func (w *creditedWriter) grant() { w.credit <- struct{}{} }

func (w *creditedWriter) Write(p []byte) (int, error) {
	<-w.credit
	return len(p), nil
}
