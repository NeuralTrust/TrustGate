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
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/stretchr/testify/require"
)

const (
	testAckFrame          = `{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged"}`
	testTerminalFrame     = `{"jsonrpc":"2.0","id":7,"result":{"notifications":[]}}`
	testToolsChangedFrame = `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`
)

// recordingSink records what the loop wrote, in order, and can be scripted to
// fail a chosen write so a transport failure needs no socket.
type recordingSink struct {
	mu         sync.Mutex
	writes     []string
	flushes    int
	frames     int
	failFrame  int
	frameErr   error
	commentErr error
}

func (s *recordingSink) Frame(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames++
	if s.failFrame == s.frames {
		return s.frameErr
	}
	s.writes = append(s.writes, string(payload))
	return nil
}

func (s *recordingSink) Comment(text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commentErr != nil {
		return s.commentErr
	}
	s.writes = append(s.writes, ": "+text)
	return nil
}

func (s *recordingSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushes++
	return nil
}

func (s *recordingSink) written() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.writes...)
}

func (s *recordingSink) flushCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushes
}

// fakeTimers drives the loop from the test goroutine, so every ordering
// assertion is deterministic and the suite contains no sleeps. The channels are
// unbuffered: a send completes only once the loop has taken the tick, which is
// the synchronization point the ordering assertions rely on.
type fakeTimers struct {
	reauth    chan time.Time
	keepalive chan time.Time
	deadline  chan time.Time
	stopped   chan struct{}
}

func newFakeTimers() (subscriptionTimers, *fakeTimers) {
	return newFakeTimersRemaining(time.Minute)
}

// newFakeTimersRemaining pins what the loop believes is left of the lease, which
// is the only input to the skip rule.
func newFakeTimersRemaining(remaining time.Duration) (subscriptionTimers, *fakeTimers) {
	fake := &fakeTimers{
		reauth:    make(chan time.Time),
		keepalive: make(chan time.Time),
		deadline:  make(chan time.Time),
		stopped:   make(chan struct{}),
	}
	var once sync.Once
	return subscriptionTimers{
		Reauth:    fake.reauth,
		Keepalive: fake.keepalive,
		Deadline:  fake.deadline,
		Remaining: func() time.Duration { return remaining },
		Stop:      func() { once.Do(func() { close(fake.stopped) }) },
	}, fake
}

func testStreamSpec(honoured appmcp.HonouredSet, timers subscriptionTimers) streamSpec {
	return streamSpec{
		honoured: honoured,
		ack:      []byte(testAckFrame),
		terminal: []byte(testTerminalFrame),
		timers:   timers,
	}
}

// testReauthSpec is a lease that honours the tools kind alone, so a test can
// prove that no other kind is emittable however the policy answers.
func testReauthSpec(policy appmcp.SubscriptionPolicy, timers subscriptionTimers) streamSpec {
	spec := testStreamSpec(honouredKinds(), timers)
	spec.identity = appmcp.LeaseIdentity{Honoured: honouredKinds()}
	spec.policy = policy
	spec.budget = time.Second
	spec.notifications = map[appmcp.NotificationKind][]byte{
		appmcp.NotificationToolsListChanged: []byte(testToolsChangedFrame),
	}
	return spec
}

// scriptedPass is one answer a policy hands back, so a table can spell out a
// sequence of ticks without any clock or upstream.
type scriptedPass struct {
	changed  []appmcp.NotificationKind
	snapshot appmcp.SurfaceSnapshot
	err      error
}

// scriptedPolicy replays scripted passes and records the snapshot each pass was
// asked to compare against. Passes beyond the script repeat the last one.
type scriptedPolicy struct {
	mu       sync.Mutex
	passes   []scriptedPass
	err      error
	observed []appmcp.SurfaceSnapshot
}

func (p *scriptedPolicy) Evaluate(
	_ context.Context,
	_ appmcp.LeaseIdentity,
	prev appmcp.SurfaceSnapshot,
) (appmcp.Evaluation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := len(p.observed)
	p.observed = append(p.observed, prev)
	if p.err != nil {
		return appmcp.Evaluation{Snapshot: prev}, p.err
	}
	if len(p.passes) == 0 {
		return appmcp.Evaluation{Snapshot: prev}, nil
	}
	if index >= len(p.passes) {
		index = len(p.passes) - 1
	}
	pass := p.passes[index]
	if pass.err != nil {
		return appmcp.Evaluation{Snapshot: prev}, pass.err
	}
	return appmcp.Evaluation{Changed: pass.changed, Snapshot: pass.snapshot}, nil
}

func (p *scriptedPolicy) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.observed)
}

func (p *scriptedPolicy) seen() []appmcp.SurfaceSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]appmcp.SurfaceSnapshot(nil), p.observed...)
}

// deadlineObservingPolicy reports how much time the pass was given, which is the
// only way to see the budget from outside the loop.
type deadlineObservingPolicy struct {
	mu   sync.Mutex
	left time.Duration
}

type blockingPolicy struct {
	started  chan context.Context
	release  chan struct{}
	canceled chan struct{}
	mu       sync.Mutex
	calls    int
	active   int
	maxAlive int
}

func (p *blockingPolicy) Evaluate(
	ctx context.Context,
	_ appmcp.LeaseIdentity,
	prev appmcp.SurfaceSnapshot,
) (appmcp.Evaluation, error) {
	p.mu.Lock()
	p.calls++
	p.active++
	if p.active > p.maxAlive {
		p.maxAlive = p.active
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()
	p.started <- ctx
	select {
	case <-p.release:
		return appmcp.Evaluation{Snapshot: prev}, nil
	case <-ctx.Done():
		p.canceled <- struct{}{}
		return appmcp.Evaluation{Snapshot: prev}, ctx.Err()
	}
}

func (p *blockingPolicy) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func (p *blockingPolicy) maxActive() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxAlive
}

func (p *deadlineObservingPolicy) Evaluate(
	ctx context.Context,
	_ appmcp.LeaseIdentity,
	prev appmcp.SurfaceSnapshot,
) (appmcp.Evaluation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		p.left = time.Until(deadline)
	}
	return appmcp.Evaluation{Snapshot: prev}, nil
}

func (p *deadlineObservingPolicy) remaining() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.left
}

func honouredKinds() appmcp.HonouredSet {
	return appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged)
}

// startLoop runs the loop on its own goroutine and returns the channel its
// outcome arrives on, so a test drives the timers and then joins.
func startLoop(ctx context.Context, sink frameSink, spec streamSpec) <-chan subscriptionOutcome {
	done := make(chan subscriptionOutcome, 1)
	go func() { done <- runSubscriptionStream(ctx, sink, spec) }()
	return done
}

func awaitOutcome(t *testing.T, done <-chan subscriptionOutcome) subscriptionOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not exit")
		return ""
	}
}

func awaitScriptedCalls(t *testing.T, policy *scriptedPolicy, want int) {
	t.Helper()
	awaitCondition(t, func() bool { return policy.calls() >= want })
}

func awaitCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !condition() {
		select {
		case <-deadline:
			t.Fatal("condition was not met")
		default:
			runtime.Gosched()
		}
	}
}

// The ack is written and flushed before the loop waits on anything, so a client
// learns the honoured subset without waiting for the first keepalive.
func TestRunSubscriptionStreamAcksBeforeAnythingElse(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	done := startLoop(context.Background(), sink, testStreamSpec(honouredKinds(), timers))

	fake.keepalive <- time.Now()
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))

	require.Equal(
		t,
		[]string{testAckFrame, ": " + sseKeepalive, testTerminalFrame},
		sink.written(),
		"the ack leads, the keepalive follows on its tick, and the terminal frame closes",
	)
	require.Equal(t, 3, sink.flushCount(), "every write reaches the socket on its own flush")
}

// An empty honoured subset has nothing to wait for, so the lease acks, writes the
// terminal frame and closes without ever entering the select.
func TestRunSubscriptionStreamEmptyHonouredSubsetClosesAtOnce(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, _ := newFakeTimers()

	outcome := runSubscriptionStream(context.Background(), sink, testStreamSpec(appmcp.HonouredSet{}, timers))

	require.Equal(t, subscriptionOutcomeAcked, outcome)
	require.Equal(t, []string{testAckFrame, testTerminalFrame}, sink.written())
}

// Every termination cause must be indistinguishable on the wire: the client sees
// the same terminal frame whether the deadline fired, the process is shutting
// down, or a frame breached the size bound.
func TestRunSubscriptionStreamTerminatesIdenticallyWhateverTheCause(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		sink  func() *recordingSink
		drive func(context.CancelFunc, *fakeTimers)
		want  subscriptionOutcome
	}{
		{
			name:  "deadline",
			sink:  func() *recordingSink { return &recordingSink{} },
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.deadline <- time.Now() },
			want:  subscriptionOutcomeDeadline,
		},
		{
			name:  "shutdown cancels the lease",
			sink:  func() *recordingSink { return &recordingSink{} },
			drive: func(cancel context.CancelFunc, _ *fakeTimers) { cancel() },
			want:  subscriptionOutcomeShutdown,
		},
		{
			name: "an oversize keepalive",
			sink: func() *recordingSink {
				return &recordingSink{commentErr: ErrFrameTooLarge}
			},
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.keepalive <- time.Now() },
			want:  subscriptionOutcomeOversize,
		},
		{
			name: "a severed connection",
			sink: func() *recordingSink {
				return &recordingSink{commentErr: errors.New("broken pipe")}
			},
			drive: func(_ context.CancelFunc, fake *fakeTimers) { fake.keepalive <- time.Now() },
			want:  subscriptionOutcomeDisconnected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := tc.sink()
			timers, fake := newFakeTimers()
			done := startLoop(ctx, sink, testStreamSpec(honouredKinds(), timers))

			tc.drive(cancel, fake)
			require.Equal(t, tc.want, awaitOutcome(t, done))

			written := sink.written()
			require.Equal(t, testTerminalFrame, written[len(written)-1])
			require.Equal(t, []string{testAckFrame, testTerminalFrame}, dropKeepalives(written))
			<-fake.stopped
		})
	}
}

// A failing ack is a dead transport, not a lease: the loop must not enter the
// select and must still release its timers.
func TestRunSubscriptionStreamAckFailureEndsTheLease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want subscriptionOutcome
	}{
		{name: "oversize ack", err: ErrFrameTooLarge, want: subscriptionOutcomeOversize},
		{name: "severed connection", err: errors.New("broken pipe"), want: subscriptionOutcomeDisconnected},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &recordingSink{failFrame: 1, frameErr: tc.err}
			timers, fake := newFakeTimers()

			outcome := runSubscriptionStream(context.Background(), sink, testStreamSpec(honouredKinds(), timers))

			require.Equal(t, tc.want, outcome)
			require.Equal(t, []string{testTerminalFrame}, sink.written())
			<-fake.stopped
		})
	}
}

// An unchanged surface is silence: the keepalive that follows the tick only
// reaches the sink if the loop survived a pass that emitted nothing.
func TestRunSubscriptionStreamUnchangedSurfaceEmitsNothing(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{passes: []scriptedPass{
		{snapshot: appmcp.SurfaceSnapshot{Tools: "aaaaaaaaaaaa"}},
		{snapshot: appmcp.SurfaceSnapshot{Tools: "aaaaaaaaaaaa"}},
	}}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	fake.reauth <- time.Now()
	fake.reauth <- time.Now()
	awaitScriptedCalls(t, policy, 2)
	fake.keepalive <- time.Now()
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))

	require.Equal(
		t,
		[]string{testAckFrame, ": " + sseKeepalive, testTerminalFrame},
		sink.written(),
		"a pass that saw no change emits nothing and ends nothing",
	)
	require.Equal(t, 2, policy.calls())
}

// Every emission is one pass's verdict: one frame per changed kind, in the
// honoured order, and nothing for a kind the lease does not honour.
func TestRunSubscriptionStreamEmitsOneFrameForEachChangedKind(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{passes: []scriptedPass{
		{
			changed:  []appmcp.NotificationKind{appmcp.NotificationToolsListChanged},
			snapshot: appmcp.SurfaceSnapshot{Tools: "bbbbbbbbbbbb"},
		},
		{
			// The prompts kind is not honoured by this lease, so a change behind
			// it can never become a frame.
			changed:  []appmcp.NotificationKind{appmcp.NotificationPromptsListChanged},
			snapshot: appmcp.SurfaceSnapshot{Tools: "bbbbbbbbbbbb"},
		},
	}}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	fake.reauth <- time.Now()
	fake.reauth <- time.Now()
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))

	require.Equal(
		t,
		[]string{testAckFrame, testToolsChangedFrame, testTerminalFrame},
		sink.written(),
	)
}

// Each pass compares against the snapshot the previous successful pass produced,
// so an inconclusive pass must not become the new baseline.
func TestRunSubscriptionStreamComparesAgainstTheLastSuccessfulSnapshot(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{passes: []scriptedPass{
		{snapshot: appmcp.SurfaceSnapshot{Tools: "aaaaaaaaaaaa"}},
		{snapshot: appmcp.SurfaceSnapshot{Tools: "zzzzzzzzzzzz", Degraded: true}},
		{snapshot: appmcp.SurfaceSnapshot{Tools: "aaaaaaaaaaaa"}},
	}}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	for range 3 {
		fake.reauth <- time.Now()
	}
	awaitScriptedCalls(t, policy, 3)
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))

	require.Equal(t, []string{testAckFrame, testTerminalFrame}, sink.written())
	require.Equal(
		t,
		[]appmcp.SurfaceSnapshot{
			{},
			{Tools: "aaaaaaaaaaaa"},
			{Tools: "aaaaaaaaaaaa"},
		},
		policy.seen(),
		"the degraded pass must not overwrite the baseline the next pass compares against",
	)
}

// A pass that cannot finish before the deadline is not started at all, so the
// terminal frame always lands with its full write margin intact.
func TestRunSubscriptionStreamSkipsAPassThatCannotFinishInTime(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimersRemaining(500 * time.Millisecond)
	policy := &scriptedPolicy{err: appmcp.ErrSubscriptionRevoked}
	spec := testReauthSpec(policy, timers)
	spec.budget = time.Second
	done := startLoop(context.Background(), sink, spec)

	fake.reauth <- time.Now()
	fake.keepalive <- time.Now()
	fake.deadline <- time.Now()

	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))
	require.Equal(t, 0, policy.calls(), "no pass may be in flight when the deadline fires")
	require.Equal(t, []string{testAckFrame, ": " + sseKeepalive, testTerminalFrame}, sink.written())
}

// The pass is bounded by the budget, not by the lease: a slow policy must not
// park the writer and starve the keepalives.
func TestRunSubscriptionStreamBoundsThePassByTheBudget(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &deadlineObservingPolicy{}
	spec := testReauthSpec(policy, timers)
	spec.budget = 3 * time.Second
	done := startLoop(context.Background(), sink, spec)

	fake.reauth <- time.Now()
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))

	remaining := policy.remaining()
	require.Greater(t, remaining, time.Duration(0), "the pass must run under a deadline of its own")
	require.LessOrEqual(t, remaining, 3*time.Second)
}

func TestRunSubscriptionStreamObservesKeepaliveAndDeadlineDuringReauth(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &blockingPolicy{
		started:  make(chan context.Context, 1),
		release:  make(chan struct{}),
		canceled: make(chan struct{}, 1),
	}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	fake.reauth <- time.Now()
	<-policy.started
	fake.keepalive <- time.Now()
	fake.deadline <- time.Now()

	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))
	require.Equal(t, []string{testAckFrame, ": " + sseKeepalive, testTerminalFrame}, sink.written())
	select {
	case <-policy.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("deadline did not cancel the in-flight pass")
	}
}

func TestRunSubscriptionStreamCancellationCancelsReauth(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &blockingPolicy{
		started:  make(chan context.Context, 1),
		release:  make(chan struct{}),
		canceled: make(chan struct{}, 1),
	}
	done := startLoop(ctx, sink, testReauthSpec(policy, timers))

	fake.reauth <- time.Now()
	<-policy.started
	cancel()

	require.Equal(t, subscriptionOutcomeShutdown, awaitOutcome(t, done))
	select {
	case <-policy.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("stream cancellation did not cancel the in-flight pass")
	}
}

func TestRunSubscriptionStreamAllowsOnlyOneReauthPass(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &blockingPolicy{
		started:  make(chan context.Context, 2),
		release:  make(chan struct{}),
		canceled: make(chan struct{}, 1),
	}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	fake.reauth <- time.Now()
	<-policy.started
	secondAccepted := make(chan struct{})
	go func() {
		fake.reauth <- time.Now()
		close(secondAccepted)
	}()
	select {
	case <-secondAccepted:
		t.Fatal("a second reauth tick was accepted while a pass was active")
	default:
	}
	require.Equal(t, 1, policy.callCount())
	close(policy.release)
	<-secondAccepted
	<-policy.started
	fake.deadline <- time.Now()

	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))
	require.Equal(t, 2, policy.callCount())
	require.Equal(t, 1, policy.maxActive())
}

// A refusal ends the lease. It never narrows the honoured subset, and it is
// indistinguishable on the wire from any other termination.
func TestRunSubscriptionStreamRevocationTerminates(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{err: appmcp.ErrSubscriptionRevoked}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	fake.reauth <- time.Now()

	require.Equal(t, subscriptionOutcomeRevoked, awaitOutcome(t, done))
	require.Equal(t, []string{testAckFrame, testTerminalFrame}, sink.written())
	<-fake.stopped
}

// An inconclusive pass is survivable, but a lease whose surface cannot be
// re-verified three times running is not: emitting against an authorization
// decision that is no longer known to hold is worse than a re-open.
func TestRunSubscriptionStreamTerminatesAfterThreeInconclusivePasses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pass scriptedPass
	}{
		{
			name: "a transient failure",
			pass: scriptedPass{err: errors.New("upstream unavailable")},
		},
		{
			name: "a degraded surface",
			pass: scriptedPass{snapshot: appmcp.SurfaceSnapshot{Tools: "cccccccccccc", Degraded: true}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &recordingSink{}
			timers, fake := newFakeTimers()
			policy := &scriptedPolicy{passes: []scriptedPass{tc.pass, tc.pass, tc.pass}}
			done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

			fake.reauth <- time.Now()
			fake.reauth <- time.Now()
			fake.reauth <- time.Now()

			require.Equal(t, subscriptionOutcomeDegraded, awaitOutcome(t, done))
			require.Equal(t, []string{testAckFrame, testTerminalFrame}, sink.written())
			require.Equal(t, maxInconclusivePasses, policy.calls())
		})
	}
}

// The counter measures consecutive failures: one good pass in between must clear
// it, or a long lease would eventually die of unrelated blips.
func TestRunSubscriptionStreamASuccessfulPassClearsTheFailureCount(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	timers, fake := newFakeTimers()
	inconclusive := scriptedPass{err: errors.New("upstream unavailable")}
	policy := &scriptedPolicy{passes: []scriptedPass{
		inconclusive,
		inconclusive,
		{snapshot: appmcp.SurfaceSnapshot{Tools: "dddddddddddd"}},
		inconclusive,
		inconclusive,
	}}
	done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

	for range 5 {
		fake.reauth <- time.Now()
	}
	fake.deadline <- time.Now()

	require.Equal(t, subscriptionOutcomeDeadline, awaitOutcome(t, done))
	require.Equal(t, []string{testAckFrame, testTerminalFrame}, sink.written())
}

// A notification that cannot be written is a dead transport, so the lease ends on
// the same terminal frame as everything else.
func TestRunSubscriptionStreamNotificationWriteFailureEndsTheLease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want subscriptionOutcome
	}{
		{name: "oversize notification", err: ErrFrameTooLarge, want: subscriptionOutcomeOversize},
		{name: "severed connection", err: errors.New("broken pipe"), want: subscriptionOutcomeDisconnected},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink := &recordingSink{failFrame: 2, frameErr: tc.err}
			timers, fake := newFakeTimers()
			policy := &scriptedPolicy{passes: []scriptedPass{{
				changed:  []appmcp.NotificationKind{appmcp.NotificationToolsListChanged},
				snapshot: appmcp.SurfaceSnapshot{Tools: "eeeeeeeeeeee"},
			}}}
			done := startLoop(context.Background(), sink, testReauthSpec(policy, timers))

			fake.reauth <- time.Now()

			require.Equal(t, tc.want, awaitOutcome(t, done))
			require.Equal(t, []string{testAckFrame, testTerminalFrame}, sink.written())
		})
	}
}

// A panic inside the loop cannot escape: fasthttp's stream goroutine is not
// wrapped by PanicRecoverMiddleware, so an unrecovered panic takes the process
// down.
func TestRunSubscriptionStreamRecoversFromAPanic(t *testing.T) {
	t.Parallel()
	timers, fake := newFakeTimers()
	sink := &panickingSink{}

	outcome := runSubscriptionStream(context.Background(), sink, testStreamSpec(honouredKinds(), timers))

	require.Equal(t, subscriptionOutcomeFailed, outcome)
	require.Equal(t, 1, sink.terminals, "a recovered panic still writes the terminal frame")
	<-fake.stopped
}

func TestNewSubscriptionTimersDrawsTheDeadlineInsideTheJitterWindow(t *testing.T) {
	t.Parallel()
	const lifetime = 10 * time.Minute
	drawn := make(map[time.Duration]struct{})

	for i := 0; i < 64; i++ {
		timers := newSubscriptionTimers(lifetime, 0, 0, subscriptionJitter)
		remaining := timers.Remaining()
		timers.Stop()

		require.Less(t, remaining, lifetime, "the deadline must never equal the configured lifetime")
		require.Greater(t, remaining, lifetime-lifetime/subscriptionJitterDivisor-time.Second)
		drawn[remaining.Round(time.Millisecond)] = struct{}{}
	}

	require.Greater(t, len(drawn), 1, "two leases with one configured lifetime must not share a deadline")
}

// The deadline is drawn once at open, so Remaining only ever counts down.
func TestNewSubscriptionTimersRemainingCountsDown(t *testing.T) {
	t.Parallel()
	timers := newSubscriptionTimers(time.Hour, 0, 0, subscriptionJitter)
	defer timers.Stop()

	first := timers.Remaining()
	require.GreaterOrEqual(t, first, timers.Remaining())
}

func TestNewSubscriptionTimersOmitsDisabledTickers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		reauth        time.Duration
		keepalive     time.Duration
		wantReauth    bool
		wantKeepalive bool
	}{
		{name: "both disabled"},
		{name: "keepalive only", keepalive: time.Minute, wantKeepalive: true},
		{name: "reauth only", reauth: time.Minute, wantReauth: true},
		{
			name:          "both armed",
			reauth:        time.Minute,
			keepalive:     time.Minute,
			wantReauth:    true,
			wantKeepalive: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			timers := newSubscriptionTimers(time.Hour, tc.reauth, tc.keepalive, subscriptionJitter)
			defer timers.Stop()

			require.Equal(t, tc.wantReauth, timers.Reauth != nil)
			require.Equal(t, tc.wantKeepalive, timers.Keepalive != nil)
			require.NotNil(t, timers.Deadline)
		})
	}
}

func TestSubscriptionJitterStaysInsideTheWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		lifetime time.Duration
	}{
		{name: "ten minutes", lifetime: 10 * time.Minute},
		{name: "one second", lifetime: time.Second},
		{name: "below the divisor", lifetime: 5 * time.Nanosecond},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < 128; i++ {
				jitter := subscriptionJitter(tc.lifetime)
				require.GreaterOrEqual(t, jitter, time.Duration(0))
				require.LessOrEqual(t, jitter, tc.lifetime/subscriptionJitterDivisor)
			}
		})
	}
}

// An unjittered lifetime is what a test injects, so the deadline must survive a
// nil jitter rather than fire at once.
func TestNewSubscriptionTimersWithoutJitterKeepsTheLifetime(t *testing.T) {
	t.Parallel()
	timers := newSubscriptionTimers(time.Hour, 0, 0, nil)
	defer timers.Stop()

	require.Greater(t, timers.Remaining(), time.Hour-time.Second)
}

func dropKeepalives(written []string) []string {
	kept := make([]string, 0, len(written))
	for _, entry := range written {
		if entry != ": "+sseKeepalive {
			kept = append(kept, entry)
		}
	}
	return kept
}

// panickingSink panics on the ack and counts terminal frames, so a test can prove
// the loop recovers and still terminates the response.
type panickingSink struct {
	terminals int
}

func (s *panickingSink) Frame(payload []byte) error {
	if string(payload) == testTerminalFrame {
		s.terminals++
		return nil
	}
	panic("sink exploded")
}

func (s *panickingSink) Comment(string) error { return nil }

func (s *panickingSink) Flush() error { return nil }
