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

package ratelimit

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startRun(t *testing.T, m *Meter) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("Run did not return after cancel")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, within time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %v: %s", within, msg)
}

func TestRunSyncsOnTheTick(t *testing.T) {
	t.Parallel()
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, newBackend(shared), newClock(midMonth), func(o *Options) { o.SyncInterval = 20 * time.Millisecond })
	startRun(t, m)

	require.NoError(t, m.Check(bg, id))
	waitFor(t, 2*time.Second, func() bool { return shared.total("t1", domain.KindQuota, "2026-10") == 1 },
		"the unit reaches the shared counter through the loop, not through the request")
}

// SIGTERM: cancelling the loop's context is what the process does on shutdown.
// What was admitted since the last tick must be in the shared counter by the
// time Run returns, or a rolling restart quietly forgives a second of traffic.
func TestRunFlushesPendingUsageOnShutdown(t *testing.T) {
	t.Parallel()
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, newBackend(shared), newClock(midMonth), func(o *Options) {
		o.SyncInterval = time.Hour
		o.DisableKick = true
	})
	stop := startRun(t, m)

	for i := 0; i < 7; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	require.EqualValues(t, 0, shared.total("t1", domain.KindQuota, "2026-10"), "nothing synced before shutdown")

	stop()
	assert.EqualValues(t, 7, shared.total("t1", domain.KindQuota, "2026-10"))
	assert.EqualValues(t, 7, shared.total("t1", domain.KindBurst, burstWindow(midMonth)))
}

func TestRunKickBringsTheSyncForwardWhenUsageReachesATenthOfTheCap(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	// cap 100 -> kick at 10 unsynced units; the tick is an hour away.
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 0})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) { o.SyncInterval = time.Hour })
	startRun(t, m)

	// The first request reads the shared total and asks for a sync of its own;
	// let both finish so they do not blur the threshold below.
	require.NoError(t, m.Check(bg, id))
	waitFor(t, 2*time.Second, func() bool { return shared.total("t1", domain.KindBurst, burstWindow(midMonth)) == 1 }, "the new tenant is synced right away")
	base := backend.calls.Load()

	for i := 0; i < 9; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, base, backend.calls.Load(), "9 of 100 is below the threshold: no early sync")

	require.NoError(t, m.Check(bg, id)) // the 10th since the last sync
	waitFor(t, 2*time.Second, func() bool { return shared.total("t1", domain.KindBurst, burstWindow(midMonth)) == 11 },
		"the tenth unit triggers an early sync")
}

func TestRunWithoutKickWaitsForTheTick(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 0})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.SyncInterval = time.Hour
		o.DisableKick = true
	})
	startRun(t, m)

	for i := 0; i < 50; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	time.Sleep(150 * time.Millisecond)
	assert.EqualValues(t, 1, backend.calls.Load(), "the cold read is the only backend call; DisableKick waits for the tick")
	assert.Zero(t, shared.total("t1", domain.KindQuota, "2026-10"), "admitted usage stays local until the tick")
}

// Early syncs are spaced: a flood must not become a flood of Redis calls.
func TestRunKickRespectsTheMinimumGapBetweenSyncs(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var stamps []time.Time
	backend := &recordingBackend{inner: newBackend(newShared()), onCall: func() {
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
	}}
	// cap 200 -> kick every 20 units. 150 requests over ~150ms would kick ~7 times.
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 200, QuotaPerMonth: 0})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.SyncInterval = time.Hour
		o.KickMinGap = 60 * time.Millisecond
	})
	startRun(t, m)

	for i := 0; i < 150; i++ {
		require.NoError(t, m.Check(bg, id))
		time.Sleep(time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(stamps), 3, "the kick fired more than once")
	// stamps[0] is the cold read, which is not a kick. The first kick follows it
	// at once because the loop has not synced yet; every kick after that waits.
	gaps := make([]time.Duration, 0, len(stamps)-2)
	for i := 2; i < len(stamps); i++ {
		gaps = append(gaps, stamps[i].Sub(stamps[i-1]))
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	assert.GreaterOrEqual(t, gaps[0], 55*time.Millisecond, "syncs closer than the gap: %v", gaps)
}

type recordingBackend struct {
	inner  *memBackend
	onCall func()
}

func (b *recordingBackend) Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error) {
	b.onCall()
	return b.inner.Sync(ctx, items)
}

// A Redis that never answers must cost the sync loop its timeout and cost a
// tenant this pod already tracks nothing. The cold read is the one request
// that waits on Redis; it runs before the hang.
func TestSlowRedisAddsNoLatencyToRequests(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	hang := make(chan struct{})
	// The call ignores its context, so the sync timeout cannot release it: the
	// hung call stays hung until cleanup.
	backend.blockIgnoresCtx.Store(true)

	// The timeout is long on purpose: the claim is that requests do not wait on
	// the hung sync, so the bound is a fraction of it that a loaded CI machine
	// cannot reach by scheduling jitter alone.
	const syncTimeout = time.Second
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1_000_000, QuotaPerMonth: 0})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.SyncInterval = 5 * time.Millisecond
		o.SyncTimeout = syncTimeout
	})
	startRun(t, m)
	// Registered after startRun so it runs first: the loop is released before
	// it is asked to stop.
	t.Cleanup(func() { close(hang) })

	require.NoError(t, m.Check(bg, id))
	waitFor(t, 2*time.Second, func() bool { return backend.calls.Load() >= 1 }, "the cold read reached the backend")
	time.Sleep(30 * time.Millisecond) // the kick sync, if queued, finishes before the hang
	backend.block.Store(&hang)
	settled := backend.calls.Load()
	waitFor(t, 5*time.Second, func() bool { return backend.calls.Load() > settled }, "the loop entered the hung sync")
	stuck := backend.calls.Load()

	var worst time.Duration
	deadline := time.Now().Add(400 * time.Millisecond)
	n := 0
	for time.Now().Before(deadline) {
		start := time.Now()
		require.NoError(t, m.Check(bg, id), "a tracked tenant does not wait on the hung sync")
		if d := time.Since(start); d > worst {
			worst = d
		}
		n++
		time.Sleep(200 * time.Microsecond)
	}
	assert.Equal(t, stuck, backend.calls.Load(), "the loop stays stuck in the hung call")
	assert.Less(t, worst, syncTimeout/4, "worst Check latency over %d requests while Redis hung", n)
}

func TestDownRedisFailsOpenAndRecovers(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	backend.fail.Store(true)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) { o.SyncInterval = 10 * time.Millisecond })
	startRun(t, m)

	for i := 0; i < 20; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	waitFor(t, 2*time.Second, func() bool { return backend.calls.Load() >= 3 }, "the loop keeps retrying")
	assert.Zero(t, shared.total("t1", domain.KindQuota, "2026-10"))

	backend.fail.Store(false)
	waitFor(t, 2*time.Second, func() bool { return shared.total("t1", domain.KindQuota, "2026-10") == 20 },
		"usage admitted during the outage reaches Redis once it is back")
}

// After the one cold read, the request path does not touch the backend again,
// however many requests and goroutines hit it.
func TestHotPathNeverCallsTheBackend(t *testing.T) {
	t.Parallel()
	backend := newBackend(newShared())
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1_000_000, QuotaPerMonth: 1_000_000})
	m := testMeter(r, backend, newClock(midMonth), nil)

	var wg sync.WaitGroup
	var admitted atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if m.Check(bg, id) == nil {
					admitted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 16000, admitted.Load())
	assert.EqualValues(t, 1, backend.calls.Load(), "one cold read, then nothing")
}

// A pod that has never seen a tenant knows nothing of what the others spent.
// Its first request brings the sync forward instead of waiting for the tick.
func TestRunAnUnseenTenantIsSyncedWithoutWaitingForTheTick(t *testing.T) {
	t.Parallel()
	shared := newShared()
	// Another pod already spent 90 of the 100.
	shared.totals["t1|"+string(domain.KindBurst)+"|"+burstWindow(midMonth)] = 90
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 0})
	m := testMeter(r, newBackend(shared), newClock(midMonth), func(o *Options) { o.SyncInterval = time.Hour })
	startRun(t, m)

	require.NoError(t, m.Check(bg, id))
	waitFor(t, 2*time.Second, func() bool { return shared.total("t1", domain.KindBurst, burstWindow(midMonth)) == 91 },
		"the first request of a tenant triggers a sync")

	admitted := 1
	for i := 0; i < 20; i++ {
		if m.Check(bg, id) == nil {
			admitted++
		}
	}
	assert.Equal(t, 10, admitted, "once it has seen the others' 90 it stops at the cap, not 20 past it")
}

func TestRunADisabledKickAlsoSilencesTheNewTenantSync(t *testing.T) {
	t.Parallel()
	backend := newBackend(newShared())
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 0})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.SyncInterval = time.Hour
		o.DisableKick = true
	})
	startRun(t, m)
	require.NoError(t, m.Check(bg, id))
	time.Sleep(100 * time.Millisecond)
	assert.EqualValues(t, 1, backend.calls.Load(), "the cold read runs; DisableKick does not add a sync")
}

// Eviction removes the slot from the map together with the mark, so a request
// that raced it simply gets a fresh one on its next lookup.
func TestMeterEvictionRacingRequestsNeverLosesOrSpins(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1_000_000, QuotaPerMonth: 0})
	m := testMeter(r, newBackend(shared), clock, func(o *Options) {
		o.IdleEviction = time.Millisecond
		o.DisableKick = true
	})

	done := make(chan struct{})
	var admitted, evictedInMap atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // the invariant: marked evicted <=> gone from the map
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			m.mu.RLock()
			for _, sl := range m.slots {
				sl.mu.Lock()
				if sl.evicted {
					evictedInMap.Add(1)
				}
				sl.mu.Unlock()
			}
			m.mu.RUnlock()
		}
	}()
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if m.Check(bg, id) == nil {
					admitted.Add(1)
				}
				clock.Advance(2 * time.Millisecond)
				time.Sleep(500 * time.Microsecond) // let the tenant go quiet between bursts
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		_ = m.SyncNow(bg)
		time.Sleep(20 * time.Microsecond)
	}
	close(done)
	wg.Wait()
	require.NoError(t, m.SyncNow(bg))
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, admitted.Load(), sumQuota(shared, "t1"),
		"every admitted request reached the shared counter")
	assert.Zero(t, evictedInMap.Load(), "an evicted slot was never left in the map for a request to find")
}

func sumQuota(s *sharedCounters, subject string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, v := range s.totals {
		if strings.HasPrefix(k, subject+"|"+string(domain.KindQuota)+"|") {
			n += v
		}
	}
	return n
}
