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
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubscriptionMultiplexerPoolsOnlyCompleteKeys(t *testing.T) {
	t.Parallel()
	t.Run("equal source keys share across subscriber identities", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("shared")
		stream := newMultiplexerTestStream(key.Capabilities)
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
			open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
				return stream, nil
			},
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		first := multiplexerTestRequest("first", "target", allSubscriptionKinds())
		second := multiplexerTestRequest("second", "target", allSubscriptionKinds())

		handleA, _, err := mux.Attach(context.Background(), []SubscriptionRequest{first})
		if err != nil {
			t.Fatalf("first Attach() error = %v", err)
		}
		handleB, _, err := mux.Attach(context.Background(), []SubscriptionRequest{second})
		if err != nil {
			t.Fatalf("second Attach() error = %v", err)
		}
		if got := connector.openCalls.Load(); got != 1 {
			t.Fatalf("Open() calls = %d, want 1", got)
		}
		handleA.Close()
		if live, _ := multiplexerCounts(mux); live != 1 {
			t.Fatalf("live listeners after shared detach = %d, want 1", live)
		}
		handleB.Close()
		assertMultiplexerEmpty(t, mux)
		closeMultiplexer(t, mux)
	})

	variants := []struct {
		name   string
		mutate func(*SubscriptionSourceKey)
	}{
		{name: "target", mutate: func(key *SubscriptionSourceKey) { key.TargetDigest = multiplexerDigest("other-target") }},
		{name: "origin", mutate: func(key *SubscriptionSourceKey) { key.OriginDigest = multiplexerDigest("other-origin") }},
		{name: "registry target", mutate: func(key *SubscriptionSourceKey) { key.RegistryTargetDigest = multiplexerDigest("other-registry") }},
		{name: "pin", mutate: func(key *SubscriptionSourceKey) { key.PinDigest = multiplexerDigest("other-pin") }},
		{name: "credential", mutate: func(key *SubscriptionSourceKey) { key.CredentialFingerprint = multiplexerDigest("other-credential") }},
		{name: "protocol", mutate: func(key *SubscriptionSourceKey) { key.ProtocolVersion = "other-protocol" }},
		{name: "capability trio", mutate: func(key *SubscriptionSourceKey) {
			key.Capabilities = ListChangedCapabilities{Tools: true, Resources: true}
		}},
	}
	for _, test := range variants {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			base := multiplexerTestKey("base")
			variant := base
			test.mutate(&variant)
			connector := &multiplexerTestConnector{}
			connector.prepare = func(_ context.Context, target Target) (PreparedSubscription, error) {
				key := base
				if target.URL == "second" {
					key = variant
				}
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			}
			connector.open = func(_ context.Context, _ Target, prepared PreparedSubscription) (SubscriptionStream, error) {
				return newMultiplexerTestStream(prepared.Capabilities), nil
			}
			mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
			first, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("first", "first", allSubscriptionKinds()),
			})
			if err != nil {
				t.Fatalf("first Attach() error = %v", err)
			}
			second, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("second", "second", allSubscriptionKinds()),
			})
			if err != nil {
				t.Fatalf("second Attach() error = %v", err)
			}
			if got := connector.openCalls.Load(); got != 2 {
				t.Fatalf("Open() calls = %d, want 2", got)
			}
			first.Close()
			second.Close()
			assertMultiplexerEmpty(t, mux)
			closeMultiplexer(t, mux)
		})
	}
}

func TestSubscriptionMultiplexerAtomicAttachCapacityAndRollback(t *testing.T) {
	t.Parallel()
	t.Run("reuse remains available at both caps", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("at-capacity")
		connector := connectorForPreparedKey(key)
		options := testMultiplexerOptions()
		options.MaxListeners = 1
		options.MaxPerOrigin = 1
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		first, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("first", "same", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("first Attach() error = %v", err)
		}
		second, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("second", "same", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("reuse Attach() error = %v", err)
		}
		if connector.openCalls.Load() != 1 {
			t.Fatalf("reuse opened %d listeners, want 1", connector.openCalls.Load())
		}
		first.Close()
		second.Close()
		closeMultiplexer(t, mux)
	})

	t.Run("global and origin caps refuse only new listeners", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			options SubscriptionMultiplexerOptions
			second  SubscriptionSourceKey
		}{
			{
				name: "global",
				options: func() SubscriptionMultiplexerOptions {
					options := testMultiplexerOptions()
					options.MaxListeners = 1
					return options
				}(),
				second: multiplexerTestKey("global-second"),
			},
			{
				name: "origin",
				options: func() SubscriptionMultiplexerOptions {
					options := testMultiplexerOptions()
					options.MaxPerOrigin = 1
					return options
				}(),
				second: func() SubscriptionSourceKey {
					key := multiplexerTestKey("origin-second")
					key.OriginDigest = multiplexerTestKey("origin-first").OriginDigest
					return key
				}(),
			},
		}
		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				firstKey := multiplexerTestKey(test.name + "-first")
				if test.name == "origin" {
					firstKey.OriginDigest = test.second.OriginDigest
				}
				connector := &multiplexerTestConnector{}
				connector.prepare = func(_ context.Context, target Target) (PreparedSubscription, error) {
					key := firstKey
					if target.URL == "second" {
						key = test.second
					}
					return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
				}
				connector.open = func(_ context.Context, _ Target, prepared PreparedSubscription) (SubscriptionStream, error) {
					return newMultiplexerTestStream(prepared.Capabilities), nil
				}
				mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, test.options)
				first, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
					multiplexerTestRequest("first", "first", allSubscriptionKinds()),
				})
				if err != nil {
					t.Fatalf("first Attach() error = %v", err)
				}
				_, _, err = mux.Attach(context.Background(), []SubscriptionRequest{
					multiplexerTestRequest("second", "second", allSubscriptionKinds()),
				})
				if !errors.Is(err, ErrSubscriptionListenerCapacity) {
					t.Fatalf("new-listener error = %v, want %v", err, ErrSubscriptionListenerCapacity)
				}
				if live, bindings := multiplexerCounts(mux); live != 1 || bindings != 1 {
					t.Fatalf("state after refusal = live %d bindings %d, want 1/1", live, bindings)
				}
				first.Close()
				closeMultiplexer(t, mux)
			})
		}
	})

	t.Run("second open failure leaves no partial state", func(t *testing.T) {
		t.Parallel()
		firstKey := multiplexerTestKey("rollback-first")
		secondKey := multiplexerTestKey("rollback-second")
		firstStream := newMultiplexerTestStream(firstKey.Capabilities)
		connector := &multiplexerTestConnector{}
		connector.prepare = func(_ context.Context, target Target) (PreparedSubscription, error) {
			key := firstKey
			if target.URL == "second" {
				key = secondKey
			}
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		}
		connector.open = func(_ context.Context, target Target, _ PreparedSubscription) (SubscriptionStream, error) {
			if target.URL == "second" {
				return nil, ErrSubscriptionAuthentication
			}
			return firstStream, nil
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		_, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("one", "first", allSubscriptionKinds()),
			multiplexerTestRequest("two", "second", allSubscriptionKinds()),
		})
		if !errors.Is(err, ErrSubscriptionAuthentication) {
			t.Fatalf("Attach() error = %v, want %v", err, ErrSubscriptionAuthentication)
		}
		assertMultiplexerEmpty(t, mux)
		select {
		case <-firstStream.closed:
		default:
			t.Fatal("first opened stream was not rolled back")
		}
		closeMultiplexer(t, mux)
	})

	t.Run("failed extension leaves an existing listener undisturbed", func(t *testing.T) {
		t.Parallel()
		existingKey := multiplexerTestKey("existing")
		failingKey := multiplexerTestKey("failing")
		existingStream := newMultiplexerTestStream(existingKey.Capabilities)
		connector := &multiplexerTestConnector{}
		connector.prepare = func(_ context.Context, target Target) (PreparedSubscription, error) {
			key := existingKey
			if target.URL == "failing" {
				key = failingKey
			}
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		}
		connector.open = func(_ context.Context, target Target, _ PreparedSubscription) (SubscriptionStream, error) {
			if target.URL == "failing" {
				return nil, ErrSubscriptionAuthentication
			}
			return existingStream, nil
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		existing, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("existing", "existing", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("existing Attach() error = %v", err)
		}
		_, _, err = mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("reuse", "existing", allSubscriptionKinds()),
			multiplexerTestRequest("failing", "failing", allSubscriptionKinds()),
		})
		if !errors.Is(err, ErrSubscriptionAuthentication) {
			t.Fatalf("extension Attach() error = %v, want %v", err, ErrSubscriptionAuthentication)
		}
		if live, bindings := multiplexerCounts(mux); live != 1 || bindings != 1 {
			t.Fatalf("existing state after rollback = live %d bindings %d, want 1/1", live, bindings)
		}
		existingStream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		assertSubscriptionEvent(t, existing, NotificationToolsListChanged)
		existing.Close()
		closeMultiplexer(t, mux)
	})

	t.Run("unrelated opens proceed concurrently", func(t *testing.T) {
		t.Parallel()
		firstKey := multiplexerTestKey("concurrent-first")
		secondKey := multiplexerTestKey("concurrent-second")
		firstOpenStarted := make(chan struct{})
		releaseFirstOpen := make(chan struct{})
		connector := &multiplexerTestConnector{
			prepare: func(_ context.Context, target Target) (PreparedSubscription, error) {
				key := firstKey
				if target.URL == "second" {
					key = secondKey
				}
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
			open: func(_ context.Context, target Target, prepared PreparedSubscription) (SubscriptionStream, error) {
				if target.URL == "first" {
					close(firstOpenStarted)
					<-releaseFirstOpen
				}
				return newMultiplexerTestStream(prepared.Capabilities), nil
			},
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		firstDone := make(chan error, 1)
		go func() {
			_, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("first", "first", allSubscriptionKinds()),
			})
			firstDone <- err
		}()
		select {
		case <-firstOpenStarted:
		case <-time.After(time.Second):
			t.Fatal("first Open() did not start")
		}
		second, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("second", "second", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("second Attach() error = %v", err)
		}
		close(releaseFirstOpen)
		if err := <-firstDone; err != nil {
			t.Fatalf("first Attach() error = %v", err)
		}
		second.Close()
		closeMultiplexer(t, mux)
	})

	t.Run("same-key waiter survives owner cancellation", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("reservation-transfer")
		firstOpenStarted := make(chan struct{})
		waiterPrepared := make(chan struct{})
		var opens atomic.Int32
		var prepares atomic.Int32
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				if prepares.Add(1) == 2 {
					close(waiterPrepared)
				}
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
			open: func(ctx context.Context, _ Target, prepared PreparedSubscription) (SubscriptionStream, error) {
				if opens.Add(1) == 1 {
					close(firstOpenStarted)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return newMultiplexerTestStream(prepared.Capabilities), nil
			},
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		ownerCtx, cancelOwner := context.WithCancel(context.Background())
		ownerDone := make(chan error, 1)
		go func() {
			_, _, err := mux.Attach(ownerCtx, []SubscriptionRequest{
				multiplexerTestRequest("owner", "same", allSubscriptionKinds()),
			})
			ownerDone <- err
		}()
		select {
		case <-firstOpenStarted:
		case <-time.After(time.Second):
			t.Fatal("owner Open() did not start")
		}
		waiterDone := make(chan struct {
			handle SubscriptionHandle
			err    error
		}, 1)
		go func() {
			handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("waiter", "same", allSubscriptionKinds()),
			})
			waiterDone <- struct {
				handle SubscriptionHandle
				err    error
			}{handle: handle, err: err}
		}()
		select {
		case <-waiterPrepared:
		case <-time.After(time.Second):
			t.Fatal("waiter Prepare() did not complete")
		}
		if got := opens.Load(); got != 1 {
			t.Fatalf("Open() calls before owner cancellation = %d, want 1", got)
		}
		select {
		case <-waiterDone:
			t.Fatal("waiter attached before reservation owner committed")
		default:
		}
		cancelOwner()
		if err := <-ownerDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("owner Attach() error = %v, want %v", err, context.Canceled)
		}
		var waiter struct {
			handle SubscriptionHandle
			err    error
		}
		select {
		case waiter = <-waiterDone:
		case <-time.After(time.Second):
			t.Fatal("same-key waiter did not take ownership")
		}
		if waiter.err != nil {
			t.Fatalf("waiter Attach() error = %v", waiter.err)
		}
		if got := opens.Load(); got != 2 {
			t.Fatalf("Open() calls = %d, want 2", got)
		}
		waiter.handle.Close()
		closeMultiplexer(t, mux)
	})

	t.Run("empty negotiated set returns no handle", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("empty")
		key.Capabilities = ListChangedCapabilities{}
		connector := connectorForPreparedKey(key)
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		handle, honoured, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("empty", "empty", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		if handle != nil || !honoured.Empty() {
			t.Fatalf("Attach() = (%v, %v), want nil empty", handle, honoured.Kinds())
		}
		assertMultiplexerEmpty(t, mux)
		closeMultiplexer(t, mux)
	})
}

func TestSubscriptionMultiplexerFanOutIsolationAndSlowConsumer(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("fanout")
	stream := newMultiplexerTestStream(key.Capabilities)
	connector := &multiplexerTestConnector{
		prepare: func(context.Context, Target) (PreparedSubscription, error) {
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		},
		open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
			return stream, nil
		},
	}
	var mux *SubscriptionMultiplexer
	lockChecks := make(chan bool, 8)
	authorize := func(
		_ context.Context,
		_ SubscriptionIdentity,
		_ SubscriptionSourceKey,
		_ NotificationKind,
	) (bool, error) {
		unlocked := mux.mu.TryLock()
		if unlocked {
			mux.mu.Unlock()
		}
		lockChecks <- unlocked
		return true, nil
	}
	options := testMultiplexerOptions()
	options.QueueCapacity = 1
	mux = newTestSubscriptionMultiplexer(t, connector, authorize, options)
	slow, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("slow", "shared", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("slow Attach() error = %v", err)
	}
	healthy, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("healthy", "shared", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("healthy Attach() error = %v", err)
	}

	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationResourcesListChanged}}
	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionEvent(t, healthy, NotificationToolsListChanged)
	assertSubscriptionQueueLength(t, slow, 1)
	for range 2 {
		select {
		case unlocked := <-lockChecks:
			if !unlocked {
				t.Fatal("authorization ran while pool mutex was held")
			}
		case <-time.After(time.Second):
			t.Fatal("authorization callback was not invoked")
		}
	}

	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionEvent(t, healthy, NotificationToolsListChanged)
	select {
	case <-slow.Done():
	case <-time.After(time.Second):
		t.Fatal("slow consumer was not terminated")
	}
	if !errors.Is(slow.Err(), ErrSubscriptionSlowConsumer) {
		t.Fatalf("slow Err() = %v, want %v", slow.Err(), ErrSubscriptionSlowConsumer)
	}
	if got := len(slow.(*subscriptionHandle).admission); got != 0 {
		t.Fatalf("slow admission budget after termination = %d, want 0", got)
	}
	select {
	case <-healthy.Done():
		t.Fatalf("healthy consumer terminated: %v", healthy.Err())
	default:
	}
	healthy.Close()
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerStalledAuthorizationDoesNotBlockOtherHandles(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("authorization-head-of-line")
	stream := newMultiplexerTestStream(key.Capabilities)
	connector := connectorForStream(key, stream)
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	authorize := func(
		ctx context.Context,
		identity SubscriptionIdentity,
		_ SubscriptionSourceKey,
		_ NotificationKind,
	) (bool, error) {
		if identity.ConsumerID != "consumer-slow" {
			return true, nil
		}
		select {
		case <-slowStarted:
		default:
			close(slowStarted)
		}
		select {
		case <-releaseSlow:
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	options := testMultiplexerOptions()
	options.AuthorizationTimeout = time.Second
	mux := newTestSubscriptionMultiplexer(t, connector, authorize, options)
	slow, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("slow", "shared", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("slow Attach() error = %v", err)
	}
	healthy, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("healthy", "shared", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("healthy Attach() error = %v", err)
	}

	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow authorization did not start")
	}
	assertSubscriptionEvent(t, healthy, NotificationToolsListChanged)
	close(releaseSlow)
	assertSubscriptionEvent(t, slow, NotificationToolsListChanged)
	slow.Close()
	healthy.Close()
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerFanOutDoesNotBlockDuringConcurrentDetach(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("fanout-detach-race")
	stream := newMultiplexerTestStream(key.Capabilities)
	options := testMultiplexerOptions()
	options.QueueCapacity = 1
	mux := newTestSubscriptionMultiplexer(t, connectorForStream(key, stream), allowSubscription, options)
	healthy, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("healthy", "shared", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("healthy Attach() error = %v", err)
	}
	for iteration := range 50 {
		victim, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest(
				fmt.Sprintf("victim-%d", iteration),
				"shared",
				NewHonouredSet(NotificationToolsListChanged),
			),
		})
		if err != nil {
			t.Fatalf("iteration %d victim Attach() error = %v", iteration, err)
		}
		closeDone := make(chan struct{})
		go func() {
			victim.Close()
			close(closeDone)
		}()
		stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		assertSubscriptionEvent(t, healthy, NotificationToolsListChanged)
		select {
		case <-closeDone:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d victim Close() blocked fan-out", iteration)
		}
		select {
		case <-healthy.Done():
			t.Fatalf("iteration %d healthy handle terminated: %v", iteration, healthy.Err())
		default:
		}
	}
	healthy.Close()
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerAdmissionIsExactlyQueueCapacity(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("exact-admission")
	stream := newMultiplexerTestStream(key.Capabilities)
	options := testMultiplexerOptions()
	options.QueueCapacity = 3
	mux := newTestSubscriptionMultiplexer(
		t,
		connectorForStream(key, stream),
		allowSubscription,
		options,
	)
	handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("exact", "target", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	for range options.QueueCapacity {
		stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	}
	assertSubscriptionQueueLength(t, handle, options.QueueCapacity)
	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionDone(t, handle, ErrSubscriptionSlowConsumer)
	if got := len(handle.(*subscriptionHandle).admission); got != 0 {
		t.Fatalf("admission count after termination = %d, want 0", got)
	}
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerRequiresEveryMatchingBinding(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("all-bindings")
	stream := newMultiplexerTestStream(key.Capabilities)
	var calls atomic.Int32
	mux := newTestSubscriptionMultiplexer(
		t,
		connectorForStream(key, stream),
		func(
			_ context.Context,
			identity SubscriptionIdentity,
			_ SubscriptionSourceKey,
			_ NotificationKind,
		) (bool, error) {
			calls.Add(1)
			return identity.ConsumerID != "consumer-denied", nil
		},
		testMultiplexerOptions(),
	)
	handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("allowed", "target", NewHonouredSet(NotificationToolsListChanged)),
		multiplexerTestRequest("denied", "target", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionDone(t, handle, ErrSubscriptionRevoked)
	if got := calls.Load(); got != 2 {
		t.Fatalf("authorization calls = %d, want 2", got)
	}
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerFreshAuthorizationOutcomes(t *testing.T) {
	t.Parallel()
	t.Run("transient failure emits nothing and retries fresh", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("transient-auth")
		stream := newMultiplexerTestStream(key.Capabilities)
		connector := connectorForStream(key, stream)
		var calls atomic.Int32
		authorize := func(context.Context, SubscriptionIdentity, SubscriptionSourceKey, NotificationKind) (bool, error) {
			if calls.Add(1) == 1 {
				return false, errors.New("temporary policy lookup failure")
			}
			return true, nil
		}
		mux := newTestSubscriptionMultiplexer(t, connector, authorize, testMultiplexerOptions())
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("transient", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		assertSubscriptionEvent(t, handle, NotificationToolsListChanged)
		if calls.Load() != 2 {
			t.Fatalf("authorization calls = %d, want 2", calls.Load())
		}
		if got := len(handle.Events()); got != 0 {
			t.Fatalf("unexpected duplicate events = %d", got)
		}
		handle.Close()
		closeMultiplexer(t, mux)
	})

	t.Run("consecutive transient failures terminate at the bound", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("transient-auth-bound")
		stream := newMultiplexerTestStream(key.Capabilities)
		connector := connectorForStream(key, stream)
		mux := newTestSubscriptionMultiplexer(
			t,
			connector,
			func(context.Context, SubscriptionIdentity, SubscriptionSourceKey, NotificationKind) (bool, error) {
				return false, errors.New("temporary policy lookup failure")
			},
			testMultiplexerOptions(),
		)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("transient-bound", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		for range maxTransientAuthorizationFailures {
			stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		}
		assertSubscriptionDone(t, handle, ErrSubscriptionTerminal)
		closeMultiplexer(t, mux)
	})

	t.Run("revocation terminates the complete handle", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("revoked-auth")
		stream := newMultiplexerTestStream(key.Capabilities)
		connector := connectorForStream(key, stream)
		mux := newTestSubscriptionMultiplexer(
			t,
			connector,
			func(context.Context, SubscriptionIdentity, SubscriptionSourceKey, NotificationKind) (bool, error) {
				return false, nil
			},
			testMultiplexerOptions(),
		)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("revoked", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		assertSubscriptionDone(t, handle, ErrSubscriptionRevoked)
		closeMultiplexer(t, mux)
		assertMultiplexerEmpty(t, mux)
	})
}

func TestSubscriptionMultiplexerWorkerFailuresIgnoreEmitSuccess(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("worker-failure-counter")
	stream := newMultiplexerTestStream(key.Capabilities)
	var calls atomic.Int32
	temporary := errors.New("temporary authorization failure")
	authorize := func(context.Context, SubscriptionIdentity, SubscriptionSourceKey, NotificationKind) (bool, error) {
		switch calls.Add(1) {
		case 1, 2, 4:
			return false, temporary
		default:
			return true, nil
		}
	}
	mux := newTestSubscriptionMultiplexer(t, connectorForStream(key, stream), authorize, testMultiplexerOptions())
	handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("worker-counter", "target", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	for want := int32(1); want <= 2; want++ {
		stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		awaitAtomicCount(t, &calls, want)
	}
	if err := handle.Authorize(context.Background(), SubscriptionEvent{
		Kind:   NotificationToolsListChanged,
		Source: key,
	}); err != nil {
		t.Fatalf("emit Authorize() error = %v", err)
	}
	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionDone(t, handle, ErrSubscriptionTerminal)
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerEmitFailuresIgnoreWorkerSuccess(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("emit-failure-counter")
	stream := newMultiplexerTestStream(key.Capabilities)
	var calls atomic.Int32
	temporary := errors.New("temporary authorization failure")
	authorize := func(context.Context, SubscriptionIdentity, SubscriptionSourceKey, NotificationKind) (bool, error) {
		switch calls.Add(1) {
		case 1, 2, 4:
			return false, temporary
		default:
			return true, nil
		}
	}
	mux := newTestSubscriptionMultiplexer(t, connectorForStream(key, stream), authorize, testMultiplexerOptions())
	handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("emit-counter", "target", NewHonouredSet(NotificationToolsListChanged)),
	})
	if err != nil {
		t.Fatalf("Attach() error = %v", err)
	}
	event := SubscriptionEvent{Kind: NotificationToolsListChanged, Source: key}
	for range 2 {
		if err := handle.Authorize(context.Background(), event); !errors.Is(err, temporary) {
			t.Fatalf("emit Authorize() error = %v, want %v", err, temporary)
		}
	}
	stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionEvent(t, handle, NotificationToolsListChanged)
	if err := handle.Authorize(context.Background(), event); !errors.Is(err, ErrSubscriptionTerminal) {
		t.Fatalf("emit Authorize() terminal error = %v, want %v", err, ErrSubscriptionTerminal)
	}
	assertSubscriptionDone(t, handle, ErrSubscriptionTerminal)
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerReconnectPreservesIdentityAndBounds(t *testing.T) {
	t.Parallel()
	reconnectable := []struct {
		name string
		err  error
	}{
		{name: "transport", err: ErrSubscriptionTransportClosed},
		{name: "terminal", err: ErrSubscriptionTerminal},
		{name: "idle", err: ErrSubscriptionIdle},
	}
	for _, test := range reconnectable {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			key := multiplexerTestKey("reconnect-" + test.name)
			first := newMultiplexerTestStream(key.Capabilities)
			first.steps <- multiplexerStreamStep{err: test.err}
			second := newMultiplexerTestStream(key.Capabilities)
			second.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
			connector := newSequenceSubscriptionConnector(
				[]PreparedSubscription{
					{Key: key, Capabilities: key.Capabilities},
					{Key: key, Capabilities: key.Capabilities},
				},
				[]SubscriptionStream{first, second},
			)
			waiter := &recordingSubscriptionWaiter{}
			options := testMultiplexerOptions()
			options.Waiter = waiter
			mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
			handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("reconnect", "target", allSubscriptionKinds()),
			})
			if err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			assertSubscriptionEvent(t, handle, NotificationToolsListChanged)
			if connector.openCalls.Load() != 2 {
				t.Fatalf("Open() calls = %d, want 2", connector.openCalls.Load())
			}
			if got := waiter.delaysSnapshot(); len(got) != 1 || got[0] != options.ReconnectBackoffMin {
				t.Fatalf("reconnect delays = %v, want [%s]", got, options.ReconnectBackoffMin)
			}
			handle.Close()
			closeMultiplexer(t, mux)
		})
	}

	t.Run("valid event resets consecutive attempts", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("attempt-reset")
		first := streamEndingWith(key.Capabilities, ErrSubscriptionTerminal)
		second := newMultiplexerTestStream(key.Capabilities)
		second.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		second.steps <- multiplexerStreamStep{err: ErrSubscriptionTerminal}
		third := newMultiplexerTestStream(key.Capabilities)
		third.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
		connector := newSequenceSubscriptionConnector(
			[]PreparedSubscription{
				{Key: key, Capabilities: key.Capabilities},
				{Key: key, Capabilities: key.Capabilities},
				{Key: key, Capabilities: key.Capabilities},
			},
			[]SubscriptionStream{first, second, third},
		)
		options := testMultiplexerOptions()
		options.ReconnectAttempts = 1
		options.Waiter = &recordingSubscriptionWaiter{}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("reset", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		assertSubscriptionEvent(t, handle, NotificationToolsListChanged)
		assertSubscriptionEvent(t, handle, NotificationToolsListChanged)
		if connector.openCalls.Load() != 3 {
			t.Fatalf("Open() calls = %d, want 3", connector.openCalls.Load())
		}
		handle.Close()
		closeMultiplexer(t, mux)
	})

	t.Run("identity drift and terminal failures do not retry", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name       string
			secondPrep PreparedSubscription
			initialErr error
			prepareErr error
			wantErr    error
		}{
			{
				name:       "source drift",
				secondPrep: PreparedSubscription{Key: multiplexerTestKey("drifted"), Capabilities: allListChangedCapabilities()},
				initialErr: ErrSubscriptionTerminal,
				wantErr:    ErrSubscriptionSourceChanged,
			},
			{
				name:       "authentication",
				initialErr: ErrSubscriptionTerminal,
				prepareErr: ErrSubscriptionAuthentication,
				wantErr:    ErrSubscriptionAuthentication,
			},
			{
				name:       "protocol",
				initialErr: ErrSubscriptionProtocol,
				wantErr:    ErrSubscriptionProtocol,
			},
		}
		for _, test := range tests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				key := multiplexerTestKey("terminal-" + test.name)
				first := streamEndingWith(key.Capabilities, test.initialErr)
				var prepareCalls atomic.Int32
				connector := &multiplexerTestConnector{}
				connector.prepare = func(context.Context, Target) (PreparedSubscription, error) {
					if prepareCalls.Add(1) == 1 {
						return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
					}
					if test.prepareErr != nil {
						return PreparedSubscription{}, test.prepareErr
					}
					return test.secondPrep, nil
				}
				connector.open = func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
					return first, nil
				}
				options := testMultiplexerOptions()
				options.Waiter = &recordingSubscriptionWaiter{}
				mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
				handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
					multiplexerTestRequest("terminal", "target", allSubscriptionKinds()),
				})
				if err != nil {
					t.Fatalf("Attach() error = %v", err)
				}
				assertSubscriptionDone(t, handle, test.wantErr)
				if test.name == "protocol" && prepareCalls.Load() != 1 {
					t.Fatalf("protocol failure Prepare() calls = %d, want 1", prepareCalls.Load())
				}
				closeMultiplexer(t, mux)
			})
		}
	})

	t.Run("every reconnect source-key dimension fails closed", func(t *testing.T) {
		t.Parallel()
		variants := []struct {
			name   string
			mutate func(*SubscriptionSourceKey)
		}{
			{name: "target", mutate: func(key *SubscriptionSourceKey) { key.TargetDigest = multiplexerDigest("drift-target") }},
			{name: "origin", mutate: func(key *SubscriptionSourceKey) { key.OriginDigest = multiplexerDigest("drift-origin") }},
			{name: "registry target", mutate: func(key *SubscriptionSourceKey) { key.RegistryTargetDigest = multiplexerDigest("drift-registry") }},
			{name: "pin", mutate: func(key *SubscriptionSourceKey) { key.PinDigest = multiplexerDigest("drift-pin") }},
			{name: "credential", mutate: func(key *SubscriptionSourceKey) { key.CredentialFingerprint = multiplexerDigest("drift-credential") }},
			{name: "protocol", mutate: func(key *SubscriptionSourceKey) { key.ProtocolVersion = "drift-protocol" }},
			{name: "capability trio", mutate: func(key *SubscriptionSourceKey) {
				key.Capabilities = ListChangedCapabilities{Tools: true}
			}},
		}
		for _, test := range variants {
			test := test
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				key := multiplexerTestKey("reconnect-drift-" + test.name)
				drifted := key
				test.mutate(&drifted)
				connector := newSequenceSubscriptionConnector(
					[]PreparedSubscription{
						{Key: key, Capabilities: key.Capabilities},
						{Key: drifted, Capabilities: drifted.Capabilities},
					},
					[]SubscriptionStream{
						streamEndingWith(key.Capabilities, ErrSubscriptionTerminal),
					},
				)
				options := testMultiplexerOptions()
				options.Waiter = &recordingSubscriptionWaiter{}
				mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
				handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
					multiplexerTestRequest("drift", "target", allSubscriptionKinds()),
				})
				if err != nil {
					t.Fatalf("Attach() error = %v", err)
				}
				assertSubscriptionDone(t, handle, ErrSubscriptionSourceChanged)
				if connector.openCalls.Load() != 1 {
					t.Fatalf("Open() calls after drift = %d, want 1", connector.openCalls.Load())
				}
				closeMultiplexer(t, mux)
			})
		}
	})

	t.Run("attempt exhaustion is typed", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("exhaustion")
		connector := newSequenceSubscriptionConnector(
			[]PreparedSubscription{
				{Key: key, Capabilities: key.Capabilities},
				{Key: key, Capabilities: key.Capabilities},
			},
			[]SubscriptionStream{
				streamEndingWith(key.Capabilities, ErrSubscriptionTerminal),
				streamEndingWith(key.Capabilities, ErrSubscriptionTerminal),
			},
		)
		options := testMultiplexerOptions()
		options.ReconnectAttempts = 1
		options.Waiter = &recordingSubscriptionWaiter{}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("exhaust", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		assertSubscriptionDone(t, handle, ErrSubscriptionReconnectExhausted)
		closeMultiplexer(t, mux)
	})

	t.Run("last detach cancels a backoff wait", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("cancel-backoff")
		waiter := newBlockingSubscriptionWaiter()
		connector := connectorForStream(key, streamEndingWith(key.Capabilities, ErrSubscriptionTerminal))
		options := testMultiplexerOptions()
		options.Waiter = waiter
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("cancel", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		select {
		case <-waiter.started:
		case <-time.After(time.Second):
			t.Fatal("reconnect wait did not start")
		}
		handle.Close()
		select {
		case <-waiter.cancelled:
		case <-time.After(time.Second):
			t.Fatal("reconnect wait was not cancelled")
		}
		assertMultiplexerEmpty(t, mux)
		closeMultiplexer(t, mux)
	})
}

func TestSubscriptionMultiplexerReconnectFreshlyResolvesTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		refresh          func(*SubscriptionRequest) error
		refreshErr       error
		wantErr          error
		wantPrepareCalls int32
	}{
		{
			name: "credential rotation",
			refresh: func(request *SubscriptionRequest) error {
				request.Target.Headers = map[string]string{"Authorization": "rotated"}
				return nil
			},
			wantErr:          ErrSubscriptionSourceChanged,
			wantPrepareCalls: 2,
		},
		{
			name:             "credential expiry",
			refreshErr:       ErrSubscriptionAuthentication,
			wantErr:          ErrSubscriptionAuthentication,
			wantPrepareCalls: 1,
		},
		{
			name: "registry target drift",
			refresh: func(request *SubscriptionRequest) error {
				request.Target.URL = "changed"
				return nil
			},
			wantErr:          ErrSubscriptionSourceChanged,
			wantPrepareCalls: 2,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			key := multiplexerTestKey("fresh-" + test.name)
			first := streamEndingWith(key.Capabilities, ErrSubscriptionTerminal)
			connector := &multiplexerTestConnector{}
			connector.prepare = func(_ context.Context, target Target) (PreparedSubscription, error) {
				current := key
				if target.URL == "changed" {
					current.TargetDigest = multiplexerDigest("changed-target")
				}
				if target.Headers["Authorization"] == "rotated" {
					current.CredentialFingerprint = multiplexerDigest("rotated-credential")
				}
				return PreparedSubscription{Key: current, Capabilities: current.Capabilities}, nil
			}
			connector.open = func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
				return first, nil
			}
			options := testMultiplexerOptions()
			options.Refresher = subscriptionTargetRefresherFunc(func(
				_ context.Context,
				request SubscriptionRequest,
			) (SubscriptionRequest, error) {
				if test.refreshErr != nil {
					return SubscriptionRequest{}, test.refreshErr
				}
				if test.refresh != nil {
					if err := test.refresh(&request); err != nil {
						return SubscriptionRequest{}, err
					}
				}
				return request, nil
			})
			mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
			handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("fresh", "initial", allSubscriptionKinds()),
			})
			if err != nil {
				t.Fatalf("Attach() error = %v", err)
			}
			assertSubscriptionDone(t, handle, test.wantErr)
			if got := connector.prepareCalls.Load(); got != test.wantPrepareCalls {
				t.Fatalf("Prepare() calls = %d, want %d", got, test.wantPrepareCalls)
			}
			closeMultiplexer(t, mux)
		})
	}
}

func TestSubscriptionMultiplexerReconnectPrunesOnlyRevokedHandle(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("shared-reconnect-prune")
	initial := newMultiplexerTestStream(key.Capabilities)
	replacement := newMultiplexerTestStream(key.Capabilities)
	var opens atomic.Int32
	connector := &multiplexerTestConnector{
		prepare: func(context.Context, Target) (PreparedSubscription, error) {
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		},
		open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
			if opens.Add(1) == 1 {
				return initial, nil
			}
			return replacement, nil
		},
	}
	authorize := func(
		_ context.Context,
		identity SubscriptionIdentity,
		_ SubscriptionSourceKey,
		_ NotificationKind,
	) (bool, error) {
		if identity.ConsumerID == "consumer-revoked" {
			return false, ErrSubscriptionRevoked
		}
		return true, nil
	}
	mux := newTestSubscriptionMultiplexer(t, connector, authorize, testMultiplexerOptions())
	revoked, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("revoked", "shared", allSubscriptionKinds()),
	})
	if err != nil {
		t.Fatalf("revoked Attach() error = %v", err)
	}
	healthy, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("healthy", "shared", allSubscriptionKinds()),
	})
	if err != nil {
		t.Fatalf("healthy Attach() error = %v", err)
	}
	initial.steps <- multiplexerStreamStep{err: ErrSubscriptionTerminal}
	assertSubscriptionDone(t, revoked, ErrSubscriptionRevoked)
	assertConnectorOpenCalls(t, connector, 2)
	select {
	case <-healthy.Done():
		t.Fatalf("healthy handle terminated during reconnect: %v", healthy.Err())
	default:
	}
	replacement.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionEvent(t, healthy, NotificationToolsListChanged)
	healthy.Close()
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerReconnectTimesOutOnlyStalledHandle(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("shared-reconnect-timeout")
	initial := newMultiplexerTestStream(key.Capabilities)
	replacement := newMultiplexerTestStream(key.Capabilities)
	var opens atomic.Int32
	connector := &multiplexerTestConnector{
		prepare: func(context.Context, Target) (PreparedSubscription, error) {
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		},
		open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
			if opens.Add(1) == 1 {
				return initial, nil
			}
			return replacement, nil
		},
	}
	stalledCancelled := make(chan struct{})
	authorize := func(
		ctx context.Context,
		identity SubscriptionIdentity,
		_ SubscriptionSourceKey,
		_ NotificationKind,
	) (bool, error) {
		if identity.ConsumerID != "consumer-stalled" {
			return true, nil
		}
		<-ctx.Done()
		select {
		case <-stalledCancelled:
		default:
			close(stalledCancelled)
		}
		return false, ctx.Err()
	}
	options := testMultiplexerOptions()
	options.AuthorizationTimeout = 20 * time.Millisecond
	mux := newTestSubscriptionMultiplexer(t, connector, authorize, options)
	stalled, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("stalled", "shared", allSubscriptionKinds()),
	})
	if err != nil {
		t.Fatalf("stalled Attach() error = %v", err)
	}
	healthy, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
		multiplexerTestRequest("healthy", "shared", allSubscriptionKinds()),
	})
	if err != nil {
		t.Fatalf("healthy Attach() error = %v", err)
	}
	initial.steps <- multiplexerStreamStep{err: ErrSubscriptionTerminal}
	select {
	case <-stalledCancelled:
	case <-time.After(time.Second):
		t.Fatal("stalled reconnect authorization was not timed out")
	}
	assertSubscriptionDone(t, stalled, ErrSubscriptionTerminal)
	assertConnectorOpenCalls(t, connector, 2)
	select {
	case <-healthy.Done():
		t.Fatalf("healthy handle terminated during reconnect: %v", healthy.Err())
	default:
	}
	replacement.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
	assertSubscriptionEvent(t, healthy, NotificationToolsListChanged)
	healthy.Close()
	closeMultiplexer(t, mux)
}

func TestSubscriptionMultiplexerCloseCancelsAndJoins(t *testing.T) {
	t.Parallel()
	t.Run("cancelled open returning nil stream does not panic", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("nil-stream-cancel")
		openStarted := make(chan struct{})
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
			open: func(ctx context.Context, _ Target, _ PreparedSubscription) (SubscriptionStream, error) {
				close(openStarted)
				<-ctx.Done()
				return nil, nil
			},
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		ctx, cancel := context.WithCancel(context.Background())
		attachDone := make(chan error, 1)
		go func() {
			_, _, err := mux.Attach(ctx, []SubscriptionRequest{
				multiplexerTestRequest("nil-stream", "target", allSubscriptionKinds()),
			})
			attachDone <- err
		}()
		select {
		case <-openStarted:
		case <-time.After(time.Second):
			t.Fatal("Open() did not start")
		}
		cancel()
		select {
		case err := <-attachDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Attach() error = %v, want %v", err, context.Canceled)
			}
		case <-time.After(time.Second):
			t.Fatal("Attach() did not return after cancellation")
		}
		assertMultiplexerEmpty(t, mux)
		closeMultiplexer(t, mux)
	})

	t.Run("close cancels an in-flight attach", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("in-flight-attach")
		openStarted := make(chan struct{})
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
			open: func(ctx context.Context, _ Target, _ PreparedSubscription) (SubscriptionStream, error) {
				close(openStarted)
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		attachDone := make(chan error, 1)
		go func() {
			_, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
				multiplexerTestRequest("in-flight", "target", allSubscriptionKinds()),
			})
			attachDone <- err
		}()
		select {
		case <-openStarted:
		case <-time.After(time.Second):
			t.Fatal("Open() did not start")
		}
		closeMultiplexer(t, mux)
		select {
		case err := <-attachDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Attach() error = %v, want %v", err, context.Canceled)
			}
		case <-time.After(time.Second):
			t.Fatal("Attach() did not unblock during Close()")
		}
		assertMultiplexerEmpty(t, mux)
	})

	t.Run("last detach cancels blocked Next and releases slots", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("blocked-next")
		stream := newMultiplexerTestStream(key.Capabilities)
		connector := connectorForStream(key, stream)
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("blocked", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		handle.Close()
		select {
		case <-stream.nextCancelled:
		case <-time.After(time.Second):
			t.Fatal("blocked Next() was not cancelled")
		}
		assertMultiplexerEmpty(t, mux)
		closeMultiplexer(t, mux)
	})

	t.Run("close deadline propagates and later join succeeds", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("close-deadline")
		stream := newUncooperativeMultiplexerTestStream(key.Capabilities)
		connector := connectorForStream(key, stream)
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("deadline", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := mux.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Close() error = %v, want %v", err, context.Canceled)
		}
		select {
		case <-handle.Done():
			t.Fatal("handle Done() closed before the listener joined")
		default:
		}
		close(stream.release)
		closeMultiplexer(t, mux)
		assertSubscriptionDone(t, handle, ErrSubscriptionTerminal)
	})

	t.Run("concurrent handle and multiplexer close is idempotent", func(t *testing.T) {
		t.Parallel()
		key := multiplexerTestKey("concurrent-close")
		connector := connectorForPreparedKey(key)
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, testMultiplexerOptions())
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("concurrent", "target", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				handle.Close()
			}()
			go func() {
				defer wg.Done()
				_ = mux.Close(context.Background())
			}()
		}
		wg.Wait()
		assertMultiplexerEmpty(t, mux)
		if _, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("late", "target", allSubscriptionKinds()),
		}); !errors.Is(err, ErrSubscriptionTerminal) {
			t.Fatalf("Attach() after Close error = %v, want %v", err, ErrSubscriptionTerminal)
		}
	})
}

func TestSubscriptionMultiplexerConcurrentStress(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for iteration := range 20 {
		keyA := multiplexerTestKey(fmt.Sprintf("stress-a-%d", iteration))
		keyB := multiplexerTestKey(fmt.Sprintf("stress-b-%d", iteration))
		var streamsMu sync.Mutex
		streams := make([]*multiplexerTestStream, 0, 4)
		connector := &multiplexerTestConnector{opened: make(chan struct{}, 8)}
		connector.prepare = func(_ context.Context, target Target) (PreparedSubscription, error) {
			key := keyA
			if target.URL == "b" {
				key = keyB
			}
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		}
		connector.open = func(_ context.Context, _ Target, prepared PreparedSubscription) (SubscriptionStream, error) {
			stream := newMultiplexerTestStream(prepared.Capabilities)
			streamsMu.Lock()
			streams = append(streams, stream)
			streamsMu.Unlock()
			return stream, nil
		}
		options := testMultiplexerOptions()
		options.MaxListeners = 2
		options.MaxPerOrigin = 2
		options.QueueCapacity = 1
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)

		handles := make([]SubscriptionHandle, 8)
		var attachWG sync.WaitGroup
		for index := range handles {
			index := index
			attachWG.Add(1)
			go func() {
				defer attachWG.Done()
				target := "a"
				if index%2 == 1 {
					target = "b"
				}
				handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
					multiplexerTestRequest(fmt.Sprintf("%d", index), target, allSubscriptionKinds()),
				})
				if err != nil {
					t.Errorf("iteration %d Attach() error = %v", iteration, err)
					return
				}
				handles[index] = handle
			}()
		}
		attachWG.Wait()
		if live, bindings := multiplexerCounts(mux); live > 2 || bindings > 8 {
			t.Fatalf("iteration %d exceeded bounds: live %d bindings %d", iteration, live, bindings)
		}
		streamsMu.Lock()
		initialStreams := append([]*multiplexerTestStream(nil), streams...)
		streamsMu.Unlock()
		if len(initialStreams) != 2 {
			t.Fatalf("iteration %d initial streams = %d, want 2", iteration, len(initialStreams))
		}
		for _, stream := range initialStreams {
			stream.steps <- multiplexerStreamStep{event: SubscriptionEvent{Kind: NotificationToolsListChanged}}
			stream.steps <- multiplexerStreamStep{err: ErrSubscriptionTerminal}
		}
		for connector.openCalls.Load() < 4 {
			select {
			case <-connector.opened:
			case <-time.After(time.Second):
				t.Fatalf("iteration %d reconnect did not open replacement listeners", iteration)
			}
		}
		var closeWG sync.WaitGroup
		for _, handle := range handles {
			if handle == nil {
				continue
			}
			closeWG.Add(1)
			go func(handle SubscriptionHandle) {
				defer closeWG.Done()
				handle.Close()
			}(handle)
		}
		closeWG.Wait()
		closeMultiplexer(t, mux)
		assertMultiplexerEmpty(t, mux)
	}
	if got := runtime.NumGoroutine(); got > baseline+8 {
		t.Fatalf("goroutines after stress = %d, baseline %d", got, baseline)
	}
}

func TestSubscriptionMultiplexerListenerGaugeReturnsToZero(t *testing.T) {
	t.Run("unsupported prepare", func(t *testing.T) {
		recorder := &recordingSubscriptionSourceRecorder{}
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				return PreparedSubscription{}, ErrSubscriptionUnsupported
			},
		}
		options := testMultiplexerOptions()
		options.Recorder = recorder
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		handle, honoured, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("unsupported", "unsupported", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		if handle != nil || !honoured.Empty() {
			t.Fatalf("unsupported attach = handle %v honoured %v, want nil/empty", handle, honoured)
		}
		closeMultiplexer(t, mux)
		recorder.requireLive(t, 0)
		recorder.requireLifecycle(t, subscriptionSourceLifecycleUnsupported)
	})

	t.Run("failed open", func(t *testing.T) {
		recorder := &recordingSubscriptionSourceRecorder{}
		key := multiplexerTestKey("failed-open")
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
			open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
				return nil, ErrSubscriptionAuthentication
			},
		}
		options := testMultiplexerOptions()
		options.Recorder = recorder
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		_, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("failed-open", "failed-open", allSubscriptionKinds()),
		})
		if !errors.Is(err, ErrSubscriptionAuthentication) {
			t.Fatalf("Attach() error = %v, want %v", err, ErrSubscriptionAuthentication)
		}
		closeMultiplexer(t, mux)
		recorder.requireLive(t, 0)
		recorder.requireLifecycle(t, subscriptionSourceLifecycleOpenFailed)
	})

	t.Run("last detach", func(t *testing.T) {
		recorder := &recordingSubscriptionSourceRecorder{}
		key := multiplexerTestKey("last-detach")
		options := testMultiplexerOptions()
		options.Recorder = recorder
		mux := newTestSubscriptionMultiplexer(
			t,
			connectorForPreparedKey(key),
			allowSubscription,
			options,
		)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("last-detach", "last-detach", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		recorder.awaitLive(t, 1)
		handle.Close()
		recorder.awaitLive(t, 0)
		recorder.requireTerminal(t, subscriptionSourceTerminalLastDetach)
		closeMultiplexer(t, mux)
	})

	t.Run("reconnect exhaustion", func(t *testing.T) {
		recorder := &recordingSubscriptionSourceRecorder{}
		key := multiplexerTestKey("reconnect-exhaustion")
		first := streamEndingWith(key.Capabilities, ErrSubscriptionTransportClosed)
		connector := &multiplexerTestConnector{
			prepare: func(context.Context, Target) (PreparedSubscription, error) {
				return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
			},
		}
		connector.open = func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
			if connector.openCalls.Load() == 1 {
				return first, nil
			}
			return nil, ErrSubscriptionTransportClosed
		}
		options := testMultiplexerOptions()
		options.ReconnectAttempts = 1
		options.Recorder = recorder
		mux := newTestSubscriptionMultiplexer(t, connector, allowSubscription, options)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("reconnect-exhaustion", "reconnect-exhaustion", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		assertSubscriptionDone(t, handle, ErrSubscriptionReconnectExhausted)
		recorder.awaitLive(t, 0)
		recorder.requireTerminal(t, subscriptionSourceTerminalReconnectExhausted)
		closeMultiplexer(t, mux)
	})

	t.Run("shutdown", func(t *testing.T) {
		recorder := &recordingSubscriptionSourceRecorder{}
		key := multiplexerTestKey("shutdown")
		options := testMultiplexerOptions()
		options.Recorder = recorder
		mux := newTestSubscriptionMultiplexer(
			t,
			connectorForPreparedKey(key),
			allowSubscription,
			options,
		)
		handle, _, err := mux.Attach(context.Background(), []SubscriptionRequest{
			multiplexerTestRequest("shutdown", "shutdown", allSubscriptionKinds()),
		})
		if err != nil {
			t.Fatalf("Attach() error = %v", err)
		}
		recorder.awaitLive(t, 1)
		closeMultiplexer(t, mux)
		assertSubscriptionDone(t, handle, ErrSubscriptionTerminal)
		recorder.awaitLive(t, 0)
		recorder.requireTerminal(t, subscriptionSourceTerminalShutdown)
	})
}

func allowSubscription(context.Context, SubscriptionIdentity, SubscriptionSourceKey, NotificationKind) (bool, error) {
	return true, nil
}

func allSubscriptionKinds() HonouredSet {
	return NewHonouredSet(
		NotificationToolsListChanged,
		NotificationPromptsListChanged,
		NotificationResourcesListChanged,
	)
}

func allListChangedCapabilities() ListChangedCapabilities {
	return ListChangedCapabilities{Tools: true, Prompts: true, Resources: true}
}

func multiplexerTestKey(seed string) SubscriptionSourceKey {
	return SubscriptionSourceKey{
		TargetDigest:          multiplexerDigest(seed + "-target"),
		OriginDigest:          multiplexerDigest(seed + "-origin"),
		RegistryTargetDigest:  multiplexerDigest(seed + "-registry"),
		PinDigest:             multiplexerDigest(seed + "-pin"),
		CredentialFingerprint: multiplexerDigest(seed + "-credential"),
		ProtocolVersion:       "2026-07-28",
		Capabilities:          allListChangedCapabilities(),
	}
}

func multiplexerDigest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func multiplexerTestRequest(identity, target string, requested HonouredSet) SubscriptionRequest {
	return SubscriptionRequest{
		Identity: SubscriptionIdentity{
			GatewayID:            "gateway-" + identity,
			ConsumerID:           "consumer-" + identity,
			PrincipalFingerprint: "principal-" + identity,
			AuthID:               "auth-" + identity,
			RegistryID:           "registry-" + identity,
			RoleScopeFingerprint: "role-" + identity,
		},
		Target:    Target{URL: target, RegistryTargetID: "registry-target-" + target},
		Requested: requested,
	}
}

type passthroughSubscriptionTargetRefresher struct{}

func (passthroughSubscriptionTargetRefresher) Refresh(
	_ context.Context,
	request SubscriptionRequest,
) (SubscriptionRequest, error) {
	return request, nil
}

type subscriptionTargetRefresherFunc func(
	context.Context,
	SubscriptionRequest,
) (SubscriptionRequest, error)

func (f subscriptionTargetRefresherFunc) Refresh(
	ctx context.Context,
	request SubscriptionRequest,
) (SubscriptionRequest, error) {
	return f(ctx, request)
}

func testMultiplexerOptions() SubscriptionMultiplexerOptions {
	return SubscriptionMultiplexerOptions{
		MaxListeners:         8,
		MaxPerOrigin:         4,
		QueueCapacity:        4,
		ReconnectAttempts:    3,
		ReconnectBackoffMin:  time.Millisecond,
		ReconnectBackoffMax:  8 * time.Millisecond,
		AuthorizationTimeout: time.Second,
		Refresher:            passthroughSubscriptionTargetRefresher{},
		Waiter:               &recordingSubscriptionWaiter{},
		Jitter:               func(delay time.Duration) time.Duration { return delay },
	}
}

func newTestSubscriptionMultiplexer(
	t *testing.T,
	connector SubscriptionConnector,
	authorize SubscriptionAuthorization,
	options SubscriptionMultiplexerOptions,
) *SubscriptionMultiplexer {
	t.Helper()
	mux, err := NewSubscriptionMultiplexer(context.Background(), connector, authorize, options)
	if err != nil {
		t.Fatalf("NewSubscriptionMultiplexer() error = %v", err)
	}
	return mux
}

func connectorForPreparedKey(key SubscriptionSourceKey) *multiplexerTestConnector {
	return connectorForStream(key, newMultiplexerTestStream(key.Capabilities))
}

func connectorForStream(
	key SubscriptionSourceKey,
	stream SubscriptionStream,
) *multiplexerTestConnector {
	return &multiplexerTestConnector{
		sourceKey: func(Target, ListChangedCapabilities) (SubscriptionSourceKey, error) {
			return key, nil
		},
		prepare: func(context.Context, Target) (PreparedSubscription, error) {
			return PreparedSubscription{Key: key, Capabilities: key.Capabilities}, nil
		},
		open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
			return stream, nil
		},
	}
}

func newSequenceSubscriptionConnector(
	prepared []PreparedSubscription,
	streams []SubscriptionStream,
) *multiplexerTestConnector {
	var mu sync.Mutex
	prepareIndex := 0
	openIndex := 0
	return &multiplexerTestConnector{
		prepare: func(context.Context, Target) (PreparedSubscription, error) {
			mu.Lock()
			defer mu.Unlock()
			if prepareIndex >= len(prepared) {
				return PreparedSubscription{}, ErrSubscriptionProtocol
			}
			result := prepared[prepareIndex]
			prepareIndex++
			return result, nil
		},
		open: func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error) {
			mu.Lock()
			defer mu.Unlock()
			if openIndex >= len(streams) {
				return nil, ErrSubscriptionProtocol
			}
			stream := streams[openIndex]
			openIndex++
			return stream, nil
		},
	}
}

func streamEndingWith(capabilities ListChangedCapabilities, err error) *multiplexerTestStream {
	stream := newMultiplexerTestStream(capabilities)
	stream.steps <- multiplexerStreamStep{err: err}
	return stream
}

func assertSubscriptionEvent(t *testing.T, handle SubscriptionHandle, kind NotificationKind) {
	t.Helper()
	select {
	case event := <-handle.Events():
		if event.Kind != kind {
			t.Fatalf("event kind = %q, want %q", event.Kind, kind)
		}
	case <-handle.Done():
		t.Fatalf("handle terminated before event: %v", handle.Err())
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %q event", kind)
	}
}

func assertSubscriptionDone(t *testing.T, handle SubscriptionHandle, want error) {
	t.Helper()
	select {
	case <-handle.Done():
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for terminal %v", want)
	}
	if !errors.Is(handle.Err(), want) {
		t.Fatalf("handle Err() = %v, want %v", handle.Err(), want)
	}
}

func assertSubscriptionQueueLength(t *testing.T, handle SubscriptionHandle, want int) {
	t.Helper()
	subscription := handle.(*subscriptionHandle)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if got := len(subscription.admission); got == want {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("subscription admission count = %d, want %d", len(subscription.admission), want)
		}
	}
}

func assertConnectorOpenCalls(t *testing.T, connector *multiplexerTestConnector, want int32) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if connector.openCalls.Load() == want {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("Open() calls = %d, want %d", connector.openCalls.Load(), want)
		}
	}
}

func awaitAtomicCount(t *testing.T, count *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if count.Load() == want {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("authorization calls = %d, want %d", count.Load(), want)
		}
	}
}

func multiplexerCounts(mux *SubscriptionMultiplexer) (int, int) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	bindings := 0
	for _, listener := range mux.pool {
		bindings += len(listener.bindings)
	}
	return mux.live, bindings
}

func assertMultiplexerEmpty(t *testing.T, mux *SubscriptionMultiplexer) {
	t.Helper()
	live, bindings := multiplexerCounts(mux)
	if live != 0 || bindings != 0 {
		t.Fatalf("multiplexer state = live %d bindings %d, want 0/0", live, bindings)
	}
}

func closeMultiplexer(t *testing.T, mux *SubscriptionMultiplexer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := mux.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type multiplexerTestConnector struct {
	sourceKey    func(Target, ListChangedCapabilities) (SubscriptionSourceKey, error)
	prepare      func(context.Context, Target) (PreparedSubscription, error)
	open         func(context.Context, Target, PreparedSubscription) (SubscriptionStream, error)
	prepareCalls atomic.Int32
	openCalls    atomic.Int32
	opened       chan struct{}
}

func (c *multiplexerTestConnector) SourceKey(
	target Target,
	capabilities ListChangedCapabilities,
) (SubscriptionSourceKey, error) {
	if c.sourceKey == nil {
		return SubscriptionSourceKey{}, ErrSubscriptionProtocol
	}
	return c.sourceKey(target, capabilities)
}

func (c *multiplexerTestConnector) Prepare(
	ctx context.Context,
	target Target,
) (PreparedSubscription, error) {
	c.prepareCalls.Add(1)
	return c.prepare(ctx, target)
}

func (c *multiplexerTestConnector) Open(
	ctx context.Context,
	target Target,
	prepared PreparedSubscription,
) (SubscriptionStream, error) {
	c.openCalls.Add(1)
	if c.opened != nil {
		c.opened <- struct{}{}
	}
	return c.open(ctx, target, prepared)
}

type multiplexerStreamStep struct {
	event SubscriptionEvent
	err   error
}

type multiplexerTestStream struct {
	ack           ListChangedCapabilities
	steps         chan multiplexerStreamStep
	closed        chan struct{}
	nextCancelled chan struct{}
	closeOnce     sync.Once
	cancelOnce    sync.Once
}

func newMultiplexerTestStream(capabilities ListChangedCapabilities) *multiplexerTestStream {
	return &multiplexerTestStream{
		ack:           capabilities,
		steps:         make(chan multiplexerStreamStep, 16),
		closed:        make(chan struct{}),
		nextCancelled: make(chan struct{}),
	}
}

func (s *multiplexerTestStream) Acknowledged() ListChangedCapabilities {
	return s.ack
}

func (s *multiplexerTestStream) Next(ctx context.Context) (SubscriptionEvent, error) {
	select {
	case <-ctx.Done():
		s.cancelOnce.Do(func() { close(s.nextCancelled) })
		return SubscriptionEvent{}, ctx.Err()
	case step := <-s.steps:
		return step.event, step.err
	}
}

func (s *multiplexerTestStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type uncooperativeMultiplexerTestStream struct {
	ack       ListChangedCapabilities
	release   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func newUncooperativeMultiplexerTestStream(
	capabilities ListChangedCapabilities,
) *uncooperativeMultiplexerTestStream {
	return &uncooperativeMultiplexerTestStream{
		ack:     capabilities,
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (s *uncooperativeMultiplexerTestStream) Acknowledged() ListChangedCapabilities {
	return s.ack
}

func (s *uncooperativeMultiplexerTestStream) Next(context.Context) (SubscriptionEvent, error) {
	<-s.release
	return SubscriptionEvent{}, ErrSubscriptionTransportClosed
}

func (s *uncooperativeMultiplexerTestStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type recordingSubscriptionWaiter struct {
	mu     sync.Mutex
	delays []time.Duration
}

type recordingSubscriptionSourceRecorder struct {
	mu        sync.Mutex
	live      int64
	lifecycle []string
	terminal  []string
}

func (r *recordingSubscriptionSourceRecorder) ListenerLive(_ context.Context, delta int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live += delta
}

func (r *recordingSubscriptionSourceRecorder) Lifecycle(_ context.Context, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lifecycle = append(r.lifecycle, outcome)
}

func (*recordingSubscriptionSourceRecorder) FanOut(context.Context, NotificationKind, string) {}

func (*recordingSubscriptionSourceRecorder) Reconnect(context.Context, string) {}

func (*recordingSubscriptionSourceRecorder) Queue(context.Context, NotificationKind, string) {}

func (r *recordingSubscriptionSourceRecorder) Terminal(_ context.Context, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.terminal = append(r.terminal, outcome)
}

func (r *recordingSubscriptionSourceRecorder) awaitLive(t *testing.T, want int64) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		r.mu.Lock()
		got := r.live
		r.mu.Unlock()
		if got == want {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("source listener live = %d, want %d", got, want)
		}
	}
}

func (r *recordingSubscriptionSourceRecorder) requireLive(t *testing.T, want int64) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.live != want {
		t.Fatalf("source listener live = %d, want %d", r.live, want)
	}
}

func (r *recordingSubscriptionSourceRecorder) requireLifecycle(t *testing.T, want string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !containsSubscriptionSourceOutcome(r.lifecycle, want) {
		t.Fatalf("source lifecycle = %v, want %q", r.lifecycle, want)
	}
}

func (r *recordingSubscriptionSourceRecorder) requireTerminal(t *testing.T, want string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !containsSubscriptionSourceOutcome(r.terminal, want) {
		t.Fatalf("source terminal = %v, want %q", r.terminal, want)
	}
}

func containsSubscriptionSourceOutcome(outcomes []string, want string) bool {
	for _, outcome := range outcomes {
		if outcome == want {
			return true
		}
	}
	return false
}

func (w *recordingSubscriptionWaiter) Wait(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	w.delays = append(w.delays, delay)
	w.mu.Unlock()
	return nil
}

func (w *recordingSubscriptionWaiter) delaysSnapshot() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.delays...)
}

type blockingSubscriptionWaiter struct {
	started   chan struct{}
	cancelled chan struct{}
	startOnce sync.Once
}

func newBlockingSubscriptionWaiter() *blockingSubscriptionWaiter {
	return &blockingSubscriptionWaiter{
		started:   make(chan struct{}),
		cancelled: make(chan struct{}),
	}
}

func (w *blockingSubscriptionWaiter) Wait(ctx context.Context, _ time.Duration) error {
	w.startOnce.Do(func() { close(w.started) })
	<-ctx.Done()
	close(w.cancelled)
	return ctx.Err()
}
