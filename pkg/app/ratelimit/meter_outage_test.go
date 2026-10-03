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
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With Redis down, a flood of requests above the kick threshold must not turn
// into a flood of sync attempts: the loop keeps its own cadence.
func TestRunDuringAnOutageSyncsOncePerIntervalNotOncePerKick(t *testing.T) {
	shared := newShared()
	backend := newBackend(shared)
	backend.fail.Store(true)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 0})
	clock := newClock(midMonth)
	m := testMeter(r, backend, clock, func(o *Options) {
		o.SyncInterval = 100 * time.Millisecond
		o.KickMinGap = 2 * time.Millisecond
	})
	startRun(t, m)

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		// 150 admits are above the kick threshold (a tenth of the burst cap);
		// the next minute starts the burst window empty again.
		for i := 0; i < 150; i++ {
			require.NoError(t, m.Check(bg, id))
		}
		clock.Advance(time.Minute)
		time.Sleep(200 * time.Microsecond)
	}
	// 1 s at a 100 ms interval is 10 ticks; the first kick may add one.
	assert.LessOrEqual(t, backend.calls.Load(), int64(14), "attempts follow the interval, not the request rate")
	assert.GreaterOrEqual(t, backend.calls.Load(), int64(5), "and the loop is still trying")
}

func TestKickIsSuppressedWhileTheLastSyncFailedAndResumesAfter(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, backend, newClock(midMonth), nil)

	require.NoError(t, m.Check(bg, id))
	backend.fail.Store(true)
	require.Error(t, m.SyncNow(bg))
	drain(m)

	for i := 0; i < 50; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	assert.Zero(t, len(m.kick), "no early sync is requested while Redis is failing")

	backend.fail.Store(false)
	require.NoError(t, m.SyncNow(bg))
	for i := 0; i < 50; i++ {
		_ = m.Check(bg, id)
	}
	assert.Equal(t, 1, len(m.kick), "kicks come back once a sync succeeds")
}

// One tenant whose item keeps failing says nothing about Redis: the call
// worked. Suppressing kicks for every other tenant because of it would turn a
// single bad key into a slower sync for the whole pod.
func TestAPoisonedTenantDoesNotSuppressKicksForAHealthyOne(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	r := newResolver()
	bad, good := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	limits := domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100}
	r.set(bad, "bad", limits)
	r.set(good, "good", limits)
	m := testMeter(r, backend, newClock(midMonth), nil)

	require.NoError(t, m.Check(bg, bad))
	require.NoError(t, m.Check(bg, good))
	poisoned := "bad"
	backend.poisoned.Store(&poisoned)
	require.Error(t, m.SyncNow(bg), "the poisoned item is reported")
	drain(m)

	for i := 0; i < 50; i++ {
		require.NoError(t, m.Check(bg, good))
	}
	assert.Equal(t, 1, len(m.kick), "the healthy tenant still asks for an early sync")
}

// The verdict is over the whole round. With one tenant per call, the chunk that
// holds the poisoned tenant fails entirely, but the other calls worked: that is
// not an outage.
func TestAPoisonedTenantAloneInItsChunkIsNotAnOutage(t *testing.T) {
	t.Parallel()
	backend := newBackend(newShared())
	r := newResolver()
	limits := domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100}
	names := []string{"bad", "good-1", "good-2"}
	gws := make([]ids.GatewayID, len(names))
	for i, name := range names {
		gws[i] = ids.New[ids.GatewayKind]()
		r.set(gws[i], name, limits)
	}
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) { o.MaxBatch = 1 })
	for _, id := range gws {
		require.NoError(t, m.Check(bg, id))
	}
	poisoned := "bad"
	backend.poisoned.Store(&poisoned)
	require.Error(t, m.SyncNow(bg), "the poisoned item is reported")
	assert.False(t, m.failing.Load(), "two of three calls worked, so Redis is not down")
}

// A round of one tenant that fails only on its own item says nothing about
// Redis either.
func TestASingleTenantRoundFailingOnItsItemIsNotAnOutage(t *testing.T) {
	t.Parallel()
	backend := newBackend(newShared())
	r, id := oneGateway("bad", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, backend, newClock(midMonth), nil)
	require.NoError(t, m.Check(bg, id))
	poisoned := "bad"
	backend.poisoned.Store(&poisoned)
	require.Error(t, m.SyncNow(bg))
	assert.False(t, m.failing.Load())
}

// Every tenant of a round with several failing is Redis being down.
func TestEveryTenantFailingInAMultiTenantRoundIsAnOutage(t *testing.T) {
	t.Parallel()
	backend := newBackend(newShared())
	r := newResolver()
	limits := domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100}
	a, b := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	r.set(a, "a", limits)
	r.set(b, "b", limits)
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) { o.MaxBatch = 1 })
	require.NoError(t, m.Check(bg, a))
	require.NoError(t, m.Check(bg, b))
	backend.fail.Store(true)
	require.Error(t, m.SyncNow(bg))
	assert.True(t, m.failing.Load())
}

func drain(m *Meter) {
	select {
	case <-m.kick:
	default:
	}
}

// How long failed usage is kept is a question of time, not of how many times
// the loop tried.
func TestRetentionIsMeasuredInTimeNotInAttempts(t *testing.T) {
	read := captureMetrics(t)
	clock := newClock(midMonth)
	shared := newShared()
	backend := newBackend(shared)
	backend.fail.Store(true)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, backend, clock, nil) // default retention: 30 s

	for i := 0; i < 4; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	for i := 0; i < 200; i++ { // far more attempts than the old bound of 30
		require.Error(t, m.SyncNow(bg))
	}
	assert.EqualValues(t, 0, read("trustgate.ratelimit.sync.dropped"), "no virtual time has passed, nothing is dropped")

	clock.Advance(31 * time.Second)
	require.Error(t, m.SyncNow(bg))
	assert.EqualValues(t, 4, read("trustgate.ratelimit.sync.dropped"), "31 s after the first failure it goes, in one attempt")
}

func TestSyncFailureWarningIsRateLimited(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	clock := newClock(midMonth)
	backend := newBackend(newShared())
	backend.fail.Store(true)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := NewMeter(r, backend, Options{Now: clock.Now}, logger)

	require.NoError(t, m.Check(bg, id))
	for i := 0; i < 20; i++ {
		require.Error(t, m.SyncNow(bg))
		clock.Advance(time.Second)
	}
	assert.Equal(t, 1, strings.Count(buf.String(), "sync failed"), "20 failures in 20 s, one warning")

	clock.Advance(30 * time.Second)
	require.Error(t, m.SyncNow(bg))
	assert.Equal(t, 2, strings.Count(buf.String(), "sync failed"), "and another once the interval has passed")
}

// The verdict counts tenants, not entries. A poisoned tenant that owns a
// retained round and a new one is two entries but still one tenant, and one
// tenant failing on its own item says nothing about Redis.
func TestAPoisonedTenantWithARetainedRoundIsNotAnOutage(t *testing.T) {
	t.Parallel()
	backend := newBackend(newShared())
	r := newResolver()
	id := ids.New[ids.GatewayKind]()
	r.set(id, "bad", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, backend, newClock(midMonth), nil)
	require.NoError(t, m.Check(bg, id))
	poisoned := "bad"
	backend.poisoned.Store(&poisoned)
	require.Error(t, m.SyncNow(bg), "the first round is retained")
	require.NoError(t, m.Check(bg, id))
	require.Error(t, m.SyncNow(bg))
	assert.False(t, m.failing.Load(), "one tenant failing is not Redis being down")
}
