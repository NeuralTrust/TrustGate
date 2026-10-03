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
	"net"
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

// The headline property of the redesign, proved against a real client: a
// request never makes a Redis call. Redis is touched only when the sync loop
// runs, and then once per round, however many requests there were.
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
	assert.Zero(t, calls.Calls(), "3000 requests, 0 Redis calls")
	assert.Empty(t, mr.Keys(), "and nothing in Redis yet: increments reach it only through the sync loop")

	require.NoError(t, m.SyncNow(bg))
	assert.Positive(t, calls.Calls(), "the sync loop is what talks to Redis")
	got, err := mr.Get("gt:rl:quota:{tenant-1}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, "3000", got, "three gateways of one tenant added to one counter")
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

	// B has not seen the tenant yet, so its first request is admitted on an
	// empty view; its first sync is what teaches it that A spent 6.
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

// A listener that accepts and never answers, behind the real store: the loop
// gives up on the sync timeout and requests are never held up.
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

	var worst time.Duration
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		start := time.Now()
		require.NoError(t, m.Check(bg, id))
		if d := time.Since(start); d > worst {
			worst = d
		}
		time.Sleep(500 * time.Microsecond)
	}
	// A fraction of the timeout: requests must not wait on the silent server.
	assert.Less(t, worst, 500*time.Millisecond/4)
}
