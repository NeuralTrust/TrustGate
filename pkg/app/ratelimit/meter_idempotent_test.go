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
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A reply lost on the wire: Redis applied the round, the pod saw a timeout.
// Sending the same deltas again must not count them twice.
func TestMeterRetryAfterALostReplyDoesNotDoubleCount(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, backend, clock, nil)

	for i := 0; i < 5; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	backend.lostReplies.Store(1)
	require.Error(t, m.SyncNow(bg))
	assert.EqualValues(t, 5, shared.total("t1", domain.KindQuota, "2026-10"), "the first attempt reached Redis")

	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 5, shared.total("t1", domain.KindQuota, "2026-10"), "the retry is a no-op for Redis")
	assert.EqualValues(t, 5, shared.total("t1", domain.KindBurst, burstWindow(midMonth)))
}

// Usage admitted between the failure and the retry travels under a new token:
// it is neither lost nor merged into the round that may already be applied.
func TestMeterUsageAfterAFailedRoundIsCountedOnceUnderItsOwnToken(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, backend, clock, nil)

	for i := 0; i < 5; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	backend.lostReplies.Store(1)
	require.Error(t, m.SyncNow(bg))

	for i := 0; i < 3; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 8, shared.total("t1", domain.KindQuota, "2026-10"), "5 once, plus the 3 that came after")

	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 8, shared.total("t1", domain.KindQuota, "2026-10"), "nothing is left to resend")
}

// The failure was real this time: nothing reached Redis, and the retry must
// still deliver everything.
func TestMeterRetryAfterARealFailureDeliversEveryRound(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, backend, clock, nil)

	backend.fail.Store(true)
	for round := 0; round < 3; round++ {
		for i := 0; i < 2; i++ {
			require.NoError(t, m.Check(bg, id))
		}
		require.Error(t, m.SyncNow(bg))
	}
	backend.fail.Store(false)
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 6, shared.total("t1", domain.KindQuota, "2026-10"))
}

// Shutdown must not abort a round already on the wire: the backend may apply it
// anyway. With a client cut short by the cancellation the pod would see an
// error for work Redis did, and resend it.
func TestRunShutdownDoesNotCancelARoundInFlight(t *testing.T) {
	t.Parallel()
	shared := newShared()
	backend := newBackend(shared)
	backend.failIfCancelled.Store(true)
	backend.blockIgnoresCtx.Store(true)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.SyncInterval = 10 * time.Millisecond
		o.DisableKick = true
		o.SyncTimeout = 2 * time.Second
	})

	for i := 0; i < 4; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	release := make(chan struct{})
	backend.block.Store(&release)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	waitFor(t, 2*time.Second, func() bool { return backend.calls.Load() >= 1 }, "the first round reaches the backend")
	cancel()
	time.Sleep(20 * time.Millisecond)
	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	assert.Zero(t, backend.cancelledCalls.Load(), "the shutdown did not cancel the round that was on the wire")
	assert.EqualValues(t, 4, shared.total("t1", domain.KindQuota, "2026-10"), "counted exactly once")
}
