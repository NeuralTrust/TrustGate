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
	"encoding/json"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testCaps() SubscriptionCaps {
	return SubscriptionCaps{MaxStreams: 8, MaxPerConsumer: 4, MaxPerPrincipal: 2}
}

func leaseKey(consumer, principal string) IsolationKey {
	return IsolationKey{
		GatewayID:  "gw",
		ConsumerID: consumer,
		Principal:  principal,
		RoleScope:  "scope",
	}
}

func TestSubscriptionRegistryClaimAccountsAndReleases(t *testing.T) {
	t.Parallel()
	registry := NewSubscriptionRegistry(testCaps())

	lease, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.NoError(t, err)
	require.Equal(t, 1, registry.Live())
	require.NoError(t, lease.Context().Err())

	lease.Release()
	require.Equal(t, 0, registry.Live())
	require.ErrorIs(t, lease.Context().Err(), context.Canceled)
}

// Release is called from the writer's defer and may also be reached after Drain
// already cancelled the lease, so it has to be idempotent to the counter.
func TestSubscriptionRegistryReleaseIsIdempotent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		prepare func(*SubscriptionRegistry, *SubscriptionLease)
	}{
		{
			name:    "released twice",
			prepare: func(_ *SubscriptionRegistry, lease *SubscriptionLease) { lease.Release() },
		},
		{
			name: "drained then released",
			prepare: func(registry *SubscriptionRegistry, _ *SubscriptionLease) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_ = registry.Drain(ctx)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			registry := NewSubscriptionRegistry(testCaps())
			lease, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
			require.NoError(t, err)

			tc.prepare(registry, lease)
			lease.Release()
			lease.Release()

			require.Equal(t, 0, registry.Live())
		})
	}
}

func TestSubscriptionRegistryRefusesAtEveryCap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		caps  SubscriptionCaps
		claim func(*SubscriptionRegistry) error
	}{
		{
			name: "process cap",
			caps: SubscriptionCaps{MaxStreams: 2, MaxPerConsumer: 16, MaxPerPrincipal: 16},
			claim: func(registry *SubscriptionRegistry) error {
				return claimN(registry, 3, func(i int) IsolationKey {
					return leaseKey("c"+strconv.Itoa(i), "p"+strconv.Itoa(i))
				})
			},
		},
		{
			name: "per-consumer cap",
			caps: SubscriptionCaps{MaxStreams: 64, MaxPerConsumer: 2, MaxPerPrincipal: 16},
			claim: func(registry *SubscriptionRegistry) error {
				return claimN(registry, 3, func(i int) IsolationKey {
					return leaseKey("c1", "p"+strconv.Itoa(i))
				})
			},
		},
		{
			name: "per-principal cap",
			caps: SubscriptionCaps{MaxStreams: 64, MaxPerConsumer: 16, MaxPerPrincipal: 2},
			claim: func(registry *SubscriptionRegistry) error {
				return claimN(registry, 3, func(i int) IsolationKey {
					return leaseKey("c"+strconv.Itoa(i), "p1")
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			registry := NewSubscriptionRegistry(tc.caps)
			err := tc.claim(registry)
			require.ErrorIs(t, err, ErrSubscriptionRefused)
			require.Equal(t, SubscriptionRefusedMessage, err.Error())
		})
	}
}

// A lease with no principal fingerprint has no principal to charge, so it is
// bounded by the consumer cap rather than sharing one anonymous bucket.
func TestSubscriptionRegistryAnonymousPrincipalUsesConsumerCap(t *testing.T) {
	t.Parallel()
	registry := NewSubscriptionRegistry(SubscriptionCaps{MaxStreams: 64, MaxPerConsumer: 3, MaxPerPrincipal: 1})

	require.NoError(t, claimN(registry, 3, func(int) IsolationKey { return leaseKey("c1", "") }))
	require.Equal(t, 3, registry.Live())
	require.ErrorIs(
		t,
		claimN(registry, 1, func(int) IsolationKey { return leaseKey("c1", "") }),
		ErrSubscriptionRefused,
	)
}

func TestSubscriptionRegistryReleaseFreesTheSlot(t *testing.T) {
	t.Parallel()
	registry := NewSubscriptionRegistry(SubscriptionCaps{MaxStreams: 1, MaxPerConsumer: 1, MaxPerPrincipal: 1})

	first, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.NoError(t, err)
	_, err = registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.ErrorIs(t, err, ErrSubscriptionRefused)

	first.Release()
	second, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.NoError(t, err)
	second.Release()
}

func TestSubscriptionRegistryConcurrentClaimsHonourTheProcessCap(t *testing.T) {
	t.Parallel()
	const (
		attempts = 256
		limit    = 16
	)
	registry := NewSubscriptionRegistry(
		SubscriptionCaps{MaxStreams: limit, MaxPerConsumer: attempts, MaxPerPrincipal: attempts},
	)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		granted  int
		refusals []string
	)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := registry.Claim(context.Background(), leaseKey("c1", "p"+strconv.Itoa(i)))
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				granted++
				return
			}
			refusals = append(refusals, err.Error())
		}(i)
	}
	wg.Wait()

	require.Equal(t, limit, granted)
	require.Equal(t, limit, registry.Live())
	require.Len(t, refusals, attempts-limit)
	for _, message := range refusals {
		require.Equal(t, SubscriptionRefusedMessage, message)
	}
}

// Once the drain begins no further lease may be admitted, so shutdown cannot
// race a new stream into the wait group it is already waiting on.
func TestSubscriptionRegistryDrainingRefusesNewClaims(t *testing.T) {
	t.Parallel()
	registry := NewSubscriptionRegistry(testCaps())
	require.NoError(t, registry.Drain(context.Background()))

	_, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.ErrorIs(t, err, ErrSubscriptionRefused)
}

func TestSubscriptionRegistryDrainCancelsEveryLeaseAndWaits(t *testing.T) {
	t.Parallel()
	const leases = 32
	registry := NewSubscriptionRegistry(
		SubscriptionCaps{MaxStreams: leases, MaxPerConsumer: leases, MaxPerPrincipal: leases},
	)

	writers := sync.WaitGroup{}
	for i := 0; i < leases; i++ {
		lease, err := registry.Claim(context.Background(), leaseKey("c1", "p"+strconv.Itoa(i)))
		require.NoError(t, err)
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-lease.Context().Done()
			lease.Release()
		}()
	}
	require.Equal(t, leases, registry.Live())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, registry.Drain(ctx))

	writers.Wait()
	require.Equal(t, 0, registry.Live())
}

func TestSubscriptionRegistryDrainReleasesCapacityBeforeWriterReturns(t *testing.T) {
	t.Parallel()
	registry := NewSubscriptionRegistry(testCaps())
	lease, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.NoError(t, err)
	writerGate := make(chan struct{})
	writerReturned := make(chan struct{})
	go func() {
		<-lease.Context().Done()
		<-writerGate
		close(writerReturned)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, registry.Drain(ctx))

	require.ErrorIs(t, lease.Context().Err(), context.Canceled)
	require.Zero(t, registry.Live())
	select {
	case <-writerReturned:
		t.Fatal("writer returned before its blocked flush was released")
	default:
	}
	close(writerGate)
	<-writerReturned
}

func TestSubscriptionRegistryNilReceiverRefuses(t *testing.T) {
	t.Parallel()
	var registry *SubscriptionRegistry

	_, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.ErrorIs(t, err, ErrSubscriptionRefused)
	require.NoError(t, registry.Drain(context.Background()))
	require.Equal(t, 0, registry.Live())
}

// The caps must not be usable as an occupancy oracle: a client that can reach
// three different caps must not be able to tell them apart, so the comparison is
// on bytes rather than on a substring or an error identity.
func TestSubscriptionRegistryRefusalIsByteIdenticalWhicheverCapWasReached(t *testing.T) {
	t.Parallel()
	refusals := map[string]error{
		"process cap": refusalFrom(t,
			SubscriptionCaps{MaxStreams: 1, MaxPerConsumer: 16, MaxPerPrincipal: 16},
			func(i int) IsolationKey { return leaseKey("c"+strconv.Itoa(i), "p"+strconv.Itoa(i)) },
		),
		"per-consumer cap": refusalFrom(t,
			SubscriptionCaps{MaxStreams: 16, MaxPerConsumer: 1, MaxPerPrincipal: 16},
			func(i int) IsolationKey { return leaseKey("c1", "p"+strconv.Itoa(i)) },
		),
		"per-principal cap": refusalFrom(t,
			SubscriptionCaps{MaxStreams: 16, MaxPerConsumer: 16, MaxPerPrincipal: 1},
			func(i int) IsolationKey { return leaseKey("c"+strconv.Itoa(i), "p1") },
		),
		"draining": drainingRefusal(t),
	}

	want := []byte(SubscriptionRefusedMessage)
	wantEncoded, err := json.Marshal(SubscriptionRefusedRPCError())
	require.NoError(t, err)
	for name, refusal := range refusals {
		require.ErrorIs(t, refusal, ErrSubscriptionRefused, name)
		require.Equal(t, want, []byte(refusal.Error()), "%s discloses which bound was reached", name)

		rpcErr := SubscriptionRefusedRPCError()
		require.Nil(t, rpcErr.Data, "%s carries data a client could read a cap out of", name)
		encoded, err := json.Marshal(rpcErr)
		require.NoError(t, err)
		require.Equal(t, wantEncoded, encoded, "%s serializes differently on the wire", name)
	}
}

// Every cap is checked and incremented under one mutex, so a burst arriving at
// once must not let two claims through the last slot of any of the three.
func TestSubscriptionRegistryConcurrentClaimsHonourEveryCap(t *testing.T) {
	t.Parallel()
	const attempts = 256
	tests := []struct {
		name  string
		caps  SubscriptionCaps
		key   func(int) IsolationKey
		limit int
	}{
		{
			name:  "process cap",
			caps:  SubscriptionCaps{MaxStreams: 12, MaxPerConsumer: attempts, MaxPerPrincipal: attempts},
			key:   func(i int) IsolationKey { return leaseKey("c"+strconv.Itoa(i), "p"+strconv.Itoa(i)) },
			limit: 12,
		},
		{
			name:  "per-consumer cap",
			caps:  SubscriptionCaps{MaxStreams: attempts, MaxPerConsumer: 5, MaxPerPrincipal: attempts},
			key:   func(i int) IsolationKey { return leaseKey("c1", "p"+strconv.Itoa(i)) },
			limit: 5,
		},
		{
			name:  "per-principal cap",
			caps:  SubscriptionCaps{MaxStreams: attempts, MaxPerConsumer: attempts, MaxPerPrincipal: 3},
			key:   func(i int) IsolationKey { return leaseKey("c"+strconv.Itoa(i), "p1") },
			limit: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			registry := NewSubscriptionRegistry(tc.caps)

			var (
				wg      sync.WaitGroup
				mu      sync.Mutex
				granted int
				refused int
			)
			for i := 0; i < attempts; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, err := registry.Claim(context.Background(), tc.key(i))
					mu.Lock()
					defer mu.Unlock()
					if err == nil {
						granted++
						return
					}
					refused++
					require.Equal(t, SubscriptionRefusedMessage, err.Error())
				}(i)
			}
			wg.Wait()

			require.Equal(t, tc.limit, granted)
			require.Equal(t, attempts-tc.limit, refused)
			require.Equal(t, tc.limit, registry.Live())
		})
	}
}

func TestSubscriptionRegistryLeavesNoGoroutineBehind(t *testing.T) {
	baseline := goroutineBaseline()

	for i := 0; i < 32; i++ {
		registry := NewSubscriptionRegistry(testCaps())
		released, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
		require.NoError(t, err)
		released.Release()

		drained, err := registry.Claim(context.Background(), leaseKey("c1", "p2"))
		require.NoError(t, err)
		writer := make(chan struct{})
		go func() {
			defer close(writer)
			<-drained.Context().Done()
			drained.Release()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		require.NoError(t, registry.Drain(ctx))
		cancel()
		<-writer

		abandoned := NewSubscriptionRegistry(testCaps())
		lease, err := abandoned.Claim(context.Background(), leaseKey("c1", "p3"))
		require.NoError(t, err)
		expired, cancelExpired := context.WithCancel(context.Background())
		cancelExpired()
		require.NoError(t, abandoned.Drain(expired))
		lease.Release()
	}

	require.LessOrEqual(t, goroutineCount(), baseline+goroutineTolerance)
}

func refusalFrom(t *testing.T, caps SubscriptionCaps, key func(int) IsolationKey) error {
	t.Helper()
	registry := NewSubscriptionRegistry(caps)
	err := claimN(registry, 17, key)
	require.Error(t, err)
	return err
}

func drainingRefusal(t *testing.T) error {
	t.Helper()
	registry := NewSubscriptionRegistry(testCaps())
	require.NoError(t, registry.Drain(context.Background()))
	_, err := registry.Claim(context.Background(), leaseKey("c1", "p1"))
	require.Error(t, err)
	return err
}

// goroutineTolerance matches the allowance the streaming provider suite uses:
// the runtime's own bookkeeping goroutines come and go independently of the code
// under test.
const goroutineTolerance = 2

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

func claimN(registry *SubscriptionRegistry, count int, key func(int) IsolationKey) error {
	for i := 0; i < count; i++ {
		if _, err := registry.Claim(context.Background(), key(i)); err != nil {
			return err
		}
	}
	return nil
}
