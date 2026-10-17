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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	ratelimitinfra "github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RedisCallCounter is a go-redis hook that counts every command and every
// command inside a pipeline that reaches the wire. It is how the tests prove a
// code path makes no Redis call at all, rather than inferring it from timing.
type RedisCallCounter struct{ n atomic.Int64 }

func (c *RedisCallCounter) DialHook(next redis.DialHook) redis.DialHook { return next }

func (c *RedisCallCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.n.Add(1)
		return next(ctx, cmd)
	}
}

func (c *RedisCallCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		c.n.Add(int64(len(cmds)))
		return next(ctx, cmds)
	}
}

func (c *RedisCallCounter) Calls() int64 { return c.n.Load() }

func countedStore(t *testing.T) (*ratelimitinfra.Store, *RedisCallCounter, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	counter := &RedisCallCounter{}
	rc.AddHook(counter)
	t.Cleanup(func() { _ = rc.Close() })
	return ratelimitinfra.NewStore(rc, discardLogger()), counter, mr
}

// A tenant this pod already tracks never makes a Redis call. The first request
// reads the shared counters once; every request after that stays in memory.
// Increments still reach Redis only through the sync loop.
func TestRequestPathMakesZeroRedisCalls(t *testing.T) {
	store, calls, mr := countedStore(t)
	r := newResolver()
	gateways := []ids.GatewayID{ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()}
	for _, g := range gateways {
		r.set(g, "tenant-1", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	}
	m := testMeter(r, store, newClock(midMonth), nil)

	var wg sync.WaitGroup
	for _, g := range gateways {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_ = m.Check(bg, g)
			}
		}()
	}
	wg.Wait()
	cold := calls.Calls()
	assert.Positive(t, cold, "the cold slot reads Redis once")
	assert.LessOrEqual(t, cold, int64(16), "3000 requests must not each call Redis, got %d", cold)
	assert.Empty(t, mr.Keys(), "a zero-delta read does not create keys; increments reach Redis only through the sync loop")

	before := calls.Calls()
	require.NoError(t, m.Check(bg, gateways[0]))
	assert.Equal(t, before, calls.Calls(), "a warm request makes no Redis call")

	require.NoError(t, m.SyncNow(bg))
	assert.Greater(t, calls.Calls(), before, "the sync loop is what writes Redis")
	got, err := mr.Get("gt:rl:quota:{tenant-1}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, "3001", got, "three gateways of one tenant added to one counter")
}

// Redis load is one pipelined round trip per pod per interval, independent of
// RPS: 10 tenants and 5000 requests still cost the same handful of commands.
func TestSyncCostIsIndependentOfRequestCount(t *testing.T) {
	store, calls, _ := countedStore(t)
	r := newResolver()
	gws := make([]ids.GatewayID, 10)
	for i := range gws {
		gws[i] = ids.New[ids.GatewayKind]()
		r.set(gws[i], "tenant-"+string(rune('a'+i)), domain.Limits{BurstPerMin: 1_000_000, QuotaPerMonth: 1_000_000})
	}
	m := testMeter(r, store, newClock(midMonth), nil)

	round := func(requestsEach int) int64 {
		for _, id := range gws {
			for i := 0; i < requestsEach; i++ {
				require.NoError(t, m.Check(bg, id))
			}
		}
		before := calls.Calls()
		require.NoError(t, m.SyncNow(bg))
		return calls.Calls() - before
	}
	round(1) // the first round also loads the script
	few := round(1)
	many := round(500)
	assert.Equal(t, few, many)
	assert.EqualValues(t, 10, many, "one script call per active tenant, all in one pipeline")
}

func TestSigtermFlushReachesRealRedis(t *testing.T) {
	store, _, mr := countedStore(t)
	r, id := oneGateway("tenant-1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, store, newClock(midMonth), func(o *Options) { o.SyncInterval = time.Hour; o.DisableKick = true })
	stop := startRun(t, m)

	for i := 0; i < 9; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	assert.Empty(t, mr.Keys())
	stop()

	got, err := mr.Get("gt:rl:quota:{tenant-1}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, "9", got)
}

// Two pods (two meters over two clients) behind one Redis converge on the same
// tenant-wide total, and a gateway of the same tenant on either pod shares it.
func TestTwoPodsShareOneQuotaThroughRealRedis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	newPod := func(r GatewayTierLoader) *Meter {
		rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rc.Close() })
		return testMeter(r, ratelimitinfra.NewStore(rc, nil), newClock(midMonth), nil)
	}
	r := newResolver()
	a, b := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	free := domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 10}
	r.set(a, "tenant-1", free)
	r.set(b, "tenant-1", free)
	podA, podB := newPod(r), newPod(r)

	for i := 0; i < 6; i++ {
		require.NoError(t, podA.Check(bg, a))
	}
	require.NoError(t, podA.SyncNow(bg))

	// B has no slot yet. Its first request reads A's 6 before deciding, then
	// its sync publishes what B itself admitted.
	admitted := 0
	require.NoError(t, podB.Check(bg, b))
	admitted++
	require.NoError(t, podB.SyncNow(bg))
	for i := 0; i < 10; i++ {
		if podB.Check(bg, b) == nil {
			admitted++
		}
	}
	assert.Equal(t, 4, admitted, "10 for the tenant across both pods and both gateways (6 on A, 4 on B), not 10 each")
}

// A listener that accepts and never answers, behind the real store: the cold
// read fails open when it times out, and a tenant already tracked is not held
// up by the sync loop waiting on the same server.
func TestUnresponsiveRedisNeverDelaysRequests(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	rc := redis.NewClient(&redis.Options{
		Addr: ln.Addr().String(), ContextTimeoutEnabled: true, MaxRetries: -1,
		DialTimeout: 500 * time.Millisecond, ReadTimeout: 500 * time.Millisecond, WriteTimeout: 500 * time.Millisecond,
	})
	t.Cleanup(func() { _ = rc.Close() })

	r, id := oneGateway("tenant-1", domain.Limits{BurstPerMin: 1_000_000, QuotaPerMonth: 0})
	m := testMeter(r, ratelimitinfra.NewStore(rc, nil), newClock(midMonth), func(o *Options) {
		o.SyncInterval = 10 * time.Millisecond
		o.SyncTimeout = 500 * time.Millisecond
	})
	startRun(t, m)

	cold := time.Now()
	require.NoError(t, m.Check(bg, id), "a failed cold read fails open")
	assert.Less(t, time.Since(cold), 2*time.Second, "the cold read stays inside its budget")

	var worst time.Duration
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		start := time.Now()
		require.NoError(t, m.Check(bg, id))
		if d := time.Since(start); d > worst {
			worst = d
		}
		time.Sleep(500 * time.Microsecond)
	}
	// A fraction of the timeout: a tracked tenant must not wait on the silent server.
	assert.Less(t, worst, 500*time.Millisecond/4)
}

// An exhausted monthly quota that this pod has no counter for must reject the
// request that discovers the gap. The shared key is not incremented, and a
// parallel burst on the same cold slot does not slip through.
func TestExhaustedQuotaWithMissingSlotRejectsTheColdRequest(t *testing.T) {
	store, _, mr := countedStore(t)
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100000"))
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, store, newClock(midMonth), nil)

	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, 100_000, ex.Limit)
	assert.Equal(t, 0, ex.Remaining)
	assert.Positive(t, ex.RetryAfter)
	headers := ex.Headers()
	assert.Equal(t, []string{ReasonQuota}, headers["X-RateLimit-Reason"])
	assert.Equal(t, []string{"100000"}, headers["X-RateLimit-Limit"])
	assert.Equal(t, []string{"0"}, headers["X-RateLimit-Remaining"])
	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got, "the rejected request is not usage")

	fresh := testMeter(r, store, newClock(midMonth), nil)
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fresh.Check(bg, id)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		ex := exceeded(t, err)
		assert.Equal(t, ReasonQuota, ex.Reason, "request %d", i)
	}
	got, err = mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got, "none of the cold burst was spent")
}

// N requests that arrive together on a cold exhausted slot all get 429, and
// they share one read of Redis. A second read would mean the burst did not
// wait for the first.
func TestColdParallelBurstReadsSharedQuotaOnce(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	reads := &evalCounter{}
	rc.AddHook(reads)
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100000"))

	release := make(chan struct{})
	backend := &holdingSync{
		inner:   ratelimitinfra.NewStore(rc, discardLogger()),
		release: release,
		entered: make(chan struct{}),
	}
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) { o.SyncTimeout = 2 * time.Second })

	const n = 8
	start := make(chan struct{})
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = m.Check(bg, id)
		}()
	}
	close(start)
	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the cold read did not start")
	}
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, 1, backend.calls.Load(), "the other requests must wait on the one cold read")
	close(release)
	wg.Wait()

	for i, err := range errs {
		ex := exceeded(t, err)
		assert.Equal(t, ReasonQuota, ex.Reason, "request %d", i)
	}
	assert.EqualValues(t, 1, backend.calls.Load(), "Redis is read exactly once")
	assert.EqualValues(t, 1, reads.n.Load(), "one script read, not one per request")
	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got)
}

// A second replica with no slot of its own still rejects its first request
// when Redis is already over the monthly quota. On the old build that replica
// answered 200 between two 429s.
func TestFreshReplicaRejectsWhenSharedQuotaIsAlreadyOver(t *testing.T) {
	store, _, mr := countedStore(t)
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100001"))
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})

	for replica := 1; replica <= 2; replica++ {
		m := testMeter(r, store, newClock(midMonth), nil)
		ex := exceeded(t, m.Check(bg, id))
		assert.Equal(t, ReasonQuota, ex.Reason, "replica %d first request", replica)
		assert.Equal(t, 0, ex.Remaining, "replica %d", replica)
	}
	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100001", got, "neither replica spent the rejected request")
}

// Idle eviction drops the in-memory counter. The next request has to load the
// shared total before it decides, and an exhausted quota rejects that request.
func TestIdleEvictionReloadsExhaustedQuota(t *testing.T) {
	store, _, mr := countedStore(t)
	clock := newClock(midMonth)
	const limit = 3
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: limit})
	m := testMeter(r, store, clock, nil)

	for i := 0; i < limit; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	require.NoError(t, m.SyncNow(bg))
	_ = exceeded(t, m.Check(bg, id))

	clock.Advance(DefaultIdleEviction + time.Minute)
	require.NoError(t, m.SyncNow(bg))
	assert.Zero(t, m.tracked(), "the quiet slot is gone")

	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, limit, ex.Limit)
	got, err := mr.Get("gt:rl:quota:{acme}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, "3", got, "the cold rejection does not spend another unit")
}

// Redis being down is not a cache miss. The cold request is admitted, which is
// the same fail-open a failed background sync already uses.
func TestColdReadWhenRedisIsDownStillFailsOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	rc := redis.NewClient(&redis.Options{
		Addr:                  addr,
		DialTimeout:           50 * time.Millisecond,
		ReadTimeout:           50 * time.Millisecond,
		WriteTimeout:          50 * time.Millisecond,
		MaxRetries:            -1,
		ContextTimeoutEnabled: true,
	})
	t.Cleanup(func() { _ = rc.Close() })
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, ratelimitinfra.NewStore(rc, discardLogger()), newClock(midMonth), func(o *Options) {
		o.SyncTimeout = 200 * time.Millisecond
	})

	require.NoError(t, m.Check(bg, id), "a backend error fails open even when the quota may be exhausted")
}

// A first read slower than the sync round trip, and inside the cold-read
// budget, still learns an exhausted quota and rejects. The sync timeout is
// left at 200 ms so a read that still used it would fail open instead.
func TestSlowColdReadRejectsExhaustedQuotaWithinItsBudget(t *testing.T) {
	store, _, mr := countedStore(t)
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100000"))
	const delay = 400 * time.Millisecond
	backend := &slowFirstSync{inner: store, delay: delay}
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.SyncTimeout = 200 * time.Millisecond
		o.ColdReadTimeout = time.Second
	})

	start := time.Now()
	ex := exceeded(t, m.Check(bg, id))
	elapsed := time.Since(start)
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, 0, ex.Remaining)
	assert.GreaterOrEqual(t, elapsed, delay)
	assert.Less(t, elapsed, time.Second+500*time.Millisecond, "the rejection lands inside the cold-read budget")
	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got, "the rejected request is not usage")
}

// Idle eviction drops the slot. The next read is cold, so it gets the cold-read
// budget: a read slower than the 200 ms sync round and inside that budget still
// rejects an exhausted quota.
func TestIdleEvictionSlowColdReadRejectsExhaustedQuota(t *testing.T) {
	store, _, mr := countedStore(t)
	clock := newClock(midMonth)
	const limit = 3
	const delay = 400 * time.Millisecond
	backend := &armedDelay{inner: store, delay: delay}
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: limit})
	m := testMeter(r, backend, clock, func(o *Options) {
		o.SyncTimeout = 200 * time.Millisecond
		o.ColdReadTimeout = time.Second
	})

	for i := 0; i < limit; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	require.NoError(t, m.SyncNow(bg))
	clock.Advance(DefaultIdleEviction + time.Minute)
	require.NoError(t, m.SyncNow(bg))
	require.Zero(t, m.tracked(), "the quiet slot is gone")

	backend.arm.Store(true)
	start := time.Now()
	ex := exceeded(t, m.Check(bg, id))
	elapsed := time.Since(start)
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, limit, ex.Limit)
	assert.GreaterOrEqual(t, elapsed, delay)
	assert.Less(t, elapsed, time.Second+500*time.Millisecond, "the rejection lands inside the cold-read budget")
	got, err := mr.Get("gt:rl:quota:{acme}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, strconv.Itoa(limit), got, "the cold rejection does not spend another unit")
}

// After the slot is evicted the pooled sockets can already be dead (the peer
// dropped them while they sat idle). The cold read closes an idle socket and
// dials, and an exhausted quota rejects that request. The idle time is short
// here so the test does not wait out the production value.
func TestEvictedSlotRejectsWhenThePooledConnectionIsStale(t *testing.T) {
	const idle = 50 * time.Millisecond
	mr := miniredis.RunT(t)
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100000"))
	rc := stalePoolClient(t, mr.Addr(), idle, time.Second)
	clock := newClock(midMonth)
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, ratelimitinfra.NewStore(rc, discardLogger()), clock, func(o *Options) {
		o.SyncTimeout = 200 * time.Millisecond
		o.ColdReadTimeout = time.Second
	})

	_ = exceeded(t, m.Check(bg, id))
	clock.Advance(DefaultIdleEviction + time.Minute)
	require.NoError(t, m.SyncNow(bg))
	require.Zero(t, m.tracked(), "the quiet slot is gone")

	time.Sleep(idle + 200*time.Millisecond)
	mr.Close()
	require.NoError(t, mr.Restart())
	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	require.Equal(t, "100000", got, "restart keeps the quota key")

	start := time.Now()
	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, 0, ex.Remaining)
	assert.Less(t, time.Since(start), time.Second+500*time.Millisecond, "the dial stays inside the cold-read budget")
	got, err = mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got, "the rejected request is not usage")
}

// The replacement dial is not a pass. Redis staying down still admits the
// request, which is the same fail-open as any other cold-read error.
func TestEvictedSlotFailsOpenWhenTheReplacementDialFails(t *testing.T) {
	read := captureMetrics(t)
	const idle = 50 * time.Millisecond
	mr := miniredis.RunT(t)
	require.NoError(t, mr.Set("gt:rl:quota:{acme}:2026-10", "100000"))
	rc := stalePoolClient(t, mr.Addr(), idle, 50*time.Millisecond)
	clock := newClock(midMonth)
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, ratelimitinfra.NewStore(rc, discardLogger()), clock, func(o *Options) {
		o.SyncTimeout = 200 * time.Millisecond
		o.ColdReadTimeout = time.Second
	})

	_ = exceeded(t, m.Check(bg, id))
	clock.Advance(DefaultIdleEviction + time.Minute)
	require.NoError(t, m.SyncNow(bg))
	require.Zero(t, m.tracked())

	time.Sleep(idle + 200*time.Millisecond)
	mr.Close()

	start := time.Now()
	require.NoError(t, m.Check(bg, id), "a dial that cannot reconnect still fails open")
	assert.Less(t, time.Since(start), 3*time.Second, "giving up stays bounded")
	assert.EqualValues(t, 1, read("trustgate.ratelimit.fail_open"))
}

// The pooled socket is already closed, and idle time has not reaped it. The
// first read fails, the one retry dials, and an exhausted quota rejects.
func TestColdReadRetriesAClosedSocketAndRejectsExhaustedQuota(t *testing.T) {
	mr := miniredis.RunT(t)
	const quotaKey = "gt:rl:quota:{acme}:2026-10"
	require.NoError(t, mr.Set(quotaKey, "100000"))
	rc := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// Hide the socket the way TLS does, so the pool's peek cannot
			// discard it before the command. The retry has to do that.
			return opaqueConn{conn}, nil
		},
		ConnMaxIdleTime:       30 * time.Minute,
		MaxRetries:            -1,
		PoolSize:              1,
		ContextTimeoutEnabled: true,
		DialTimeout:           time.Second,
		ReadTimeout:           time.Second,
		WriteTimeout:          time.Second,
		PoolTimeout:           time.Second,
	})
	t.Cleanup(func() { _ = rc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, rc.Ping(ctx).Err())

	mr.Close()
	require.NoError(t, mr.Restart())
	got, err := mr.Get(quotaKey)
	require.NoError(t, err)
	require.Equal(t, "100000", got, "restart keeps the quota key")

	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	m := testMeter(r, ratelimitinfra.NewStore(rc, discardLogger()), newClock(midMonth), func(o *Options) {
		o.SyncTimeout = 200 * time.Millisecond
		o.ColdReadTimeout = time.Second
	})
	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, 0, ex.Remaining)
	got, err = mr.Get(quotaKey)
	require.NoError(t, err)
	assert.Equal(t, "100000", got, "the rejected request is not usage")
}

// A hard Redis error is not a slow read. The request is admitted, and the
// fail-open is counted against the tenant.
func TestColdReadHardErrorStillFailsOpen(t *testing.T) {
	read := captureMetrics(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	r, id := oneGateway("acme", domain.Limits{BurstPerMin: 100_000, QuotaPerMonth: 100_000})
	backend := &failingSync{err: errors.New("redis down")}
	m := NewMeter(r, backend, Options{
		Now:             newClock(midMonth).Now,
		ColdReadTimeout: time.Second,
		SyncTimeout:     200 * time.Millisecond,
	}, logger)

	require.NoError(t, m.Check(bg, id), "a hard backend error fails open")
	assert.EqualValues(t, 1, backend.calls.Load(), "a hard error is not retried")
	assert.EqualValues(t, 1, read("trustgate.ratelimit.fail_open"))
	assert.Contains(t, logs.String(), "acme")
	assert.Contains(t, logs.String(), "cold counter read failed")
}

// holdingSync stalls the first Sync until release is closed. The burst in
// TestColdParallelBurstReadsSharedQuotaOnce piles up on that one read.
type holdingSync struct {
	inner   SyncBackend
	release chan struct{}
	entered chan struct{}
	calls   atomic.Int64
}

func (h *holdingSync) Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error) {
	if h.calls.Add(1) == 1 {
		close(h.entered)
		select {
		case <-h.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return h.inner.Sync(ctx, items)
}

// evalCounter counts EVAL and EVALSHA. Handshake and SCRIPT LOAD are not reads
// of the quota key.
type evalCounter struct{ n atomic.Int64 }

func (c *evalCounter) DialHook(next redis.DialHook) redis.DialHook { return next }

func (c *evalCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if isEvalCommand(cmd) {
			c.n.Add(1)
		}
		return next(ctx, cmd)
	}
}

func (c *evalCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if isEvalCommand(cmd) {
				c.n.Add(1)
			}
		}
		return next(ctx, cmds)
	}
}

// armedDelay holds the next Sync after arm is set, and gives up when the
// call's context ends, so a budget shorter than delay fails open.
type armedDelay struct {
	inner SyncBackend
	delay time.Duration
	arm   atomic.Bool
}

func (a *armedDelay) Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error) {
	if a.arm.CompareAndSwap(true, false) {
		timer := time.NewTimer(a.delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
	return a.inner.Sync(ctx, items)
}

// opaqueConn hides the socket the way a TLS session does, so the pool cannot
// peek a reset. stalePoolClient is the sync pool with that wrapper and a short
// idle time.
type opaqueConn struct{ net.Conn }

func stalePoolClient(t *testing.T, addr string, idle, dial time.Duration) *redis.Client {
	t.Helper()
	rc := redis.NewClient(&redis.Options{
		Addr: addr,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return opaqueConn{conn}, nil
		},
		ConnMaxIdleTime:       idle,
		MaxRetries:            -1,
		PoolSize:              2,
		MinIdleConns:          1,
		ContextTimeoutEnabled: true,
		DialTimeout:           dial,
		ReadTimeout:           time.Second,
		WriteTimeout:          time.Second,
		PoolTimeout:           time.Second,
	})
	t.Cleanup(func() { _ = rc.Close() })
	return rc
}

// slowFirstSync holds only the first Sync, and it gives up when the call's
// context ends, so a budget shorter than delay fails open.
type slowFirstSync struct {
	inner SyncBackend
	delay time.Duration
	calls atomic.Int64
}

func (s *slowFirstSync) Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error) {
	if s.calls.Add(1) == 1 {
		timer := time.NewTimer(s.delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
	return s.inner.Sync(ctx, items)
}

type failingSync struct {
	err   error
	calls atomic.Int64
}

func (f *failingSync) Sync(context.Context, []domain.SyncItem) ([]domain.SyncResult, error) {
	f.calls.Add(1)
	return nil, f.err
}

func isEvalCommand(cmd redis.Cmder) bool {
	switch strings.ToLower(cmd.Name()) {
	case "eval", "evalsha":
		return true
	default:
		return false
	}
}
