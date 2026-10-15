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
	"errors"
	"sync"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var bg = context.Background()

func exceeded(t *testing.T, err error) *Exceeded {
	t.Helper()
	var ex *Exceeded
	require.True(t, errors.As(err, &ex), "want *Exceeded, got %v", err)
	return ex
}

func oneGateway(subject string, limits domain.Limits) (*stubResolver, ids.GatewayID) {
	r := newResolver()
	id := ids.New[ids.GatewayKind]()
	r.set(id, subject, limits)
	return r, id
}

func TestMeterBurstExceededCarriesLimitAndRetryAfter(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth) // 12:00:10 -> 50s left in the minute
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 5, QuotaPerMonth: 1000})
	m := testMeter(r, newBackend(newShared()), clock, nil)

	for i := 0; i < 5; i++ {
		require.NoError(t, m.Check(bg, id), "request %d", i+1)
	}
	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonBurst, ex.Reason)
	assert.Equal(t, 5, ex.Limit)
	assert.Equal(t, 0, ex.Remaining)
	assert.Equal(t, 50*time.Second, ex.RetryAfter, "Retry-After comes from the cached minute, not from Redis")
}

func TestMeterQuotaExceededRetriesAtNextMonth(t *testing.T) {
	t.Parallel()
	clock := newClock(time.Date(2026, time.October, 31, 23, 0, 0, 0, time.UTC))
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 3})
	m := testMeter(r, newBackend(newShared()), clock, nil)

	for i := 0; i < 3; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonQuota, ex.Reason)
	assert.Equal(t, 3, ex.Limit)
	assert.Equal(t, time.Hour, ex.RetryAfter)
}

func TestMeterBurstResetsWhenTheMinuteRollsOver(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 2, QuotaPerMonth: 0})
	m := testMeter(r, newBackend(newShared()), clock, nil)

	require.NoError(t, m.Check(bg, id))
	require.NoError(t, m.Check(bg, id))
	_ = exceeded(t, m.Check(bg, id))

	clock.Advance(time.Minute)
	require.NoError(t, m.Check(bg, id), "a new calendar minute is a new burst bucket")
}

// The plan's own 429 is not usage. Counting it would let a client that keeps
// retrying push the tenant's counter far past the cap on rejected traffic alone.
func TestMeterOwn429DoesNotAddToTheDelta(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 3, QuotaPerMonth: 1000})
	m := testMeter(r, newBackend(shared), clock, nil)

	for i := 0; i < 3; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	for i := 0; i < 50; i++ {
		_ = exceeded(t, m.Check(bg, id))
	}
	require.NoError(t, m.SyncNow(bg))

	assert.EqualValues(t, 3, shared.total("t1", domain.KindBurst, burstWindow(midMonth)))
	assert.EqualValues(t, 3, shared.total("t1", domain.KindQuota, "2026-10"))
}

func TestMeterTwoGatewaysOfOneTenantShareOneCounter(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	r := newResolver()
	a, b := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	free := domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 10}
	r.set(a, "tenant-1", free)
	r.set(b, "tenant-1", free)
	m := testMeter(r, newBackend(newShared()), clock, nil)

	admitted := 0
	for i := 0; i < 20; i++ {
		id := a
		if i%2 == 1 {
			id = b
		}
		if m.Check(bg, id) == nil {
			admitted++
		}
	}
	assert.Equal(t, 10, admitted, "free is 10k for the tenant, not 10k per gateway")
}

func TestMeterTenantsAreIndependent(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	r := newResolver()
	a, b := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	r.set(a, "tenant-a", domain.Limits{BurstPerMin: 2})
	r.set(b, "tenant-b", domain.Limits{BurstPerMin: 2})
	m := testMeter(r, newBackend(newShared()), clock, nil)

	require.NoError(t, m.Check(bg, a))
	require.NoError(t, m.Check(bg, a))
	_ = exceeded(t, m.Check(bg, a))
	require.NoError(t, m.Check(bg, b), "tenant-b has spent nothing")
}

func TestMeterTierChangeAppliesWithoutWaitingForASync(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 10, QuotaPerMonth: 1000})
	backend := newBackend(newShared())
	m := testMeter(r, backend, clock, nil)

	for i := 0; i < 4; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	r.set(id, "t1", domain.Limits{BurstPerMin: 4, QuotaPerMonth: 1000}) // downgrade
	_ = exceeded(t, m.Check(bg, id))

	r.set(id, "t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 1000}) // upgrade
	require.NoError(t, m.Check(bg, id))
	assert.Zero(t, backend.calls.Load(), "no sync was involved")
}

// Q4: a plan with no monthly cap still has its usage counted, so the number
// exists the day the plan gets one.
func TestMeterCountsQuotaForAnUnlimitedPlan(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 0})
	m := testMeter(r, newBackend(shared), clock, nil)

	for i := 0; i < 7; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 7, shared.total("t1", domain.KindQuota, "2026-10"))
}

func TestMeterPodsLearnTheTenantWideTotalFromTheSync(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 4})
	podA := testMeter(r, newBackend(shared), clock, nil)
	podB := testMeter(r, newBackend(shared), clock, nil)

	for i := 0; i < 3; i++ {
		require.NoError(t, podA.Check(bg, id))
	}
	require.NoError(t, podA.SyncNow(bg))
	require.NoError(t, podB.Check(bg, id), "B has not synced yet and admits on its own view")
	require.NoError(t, podB.SyncNow(bg))

	// B now sees 3 (from A) + 1 (its own) = 4 = the cap.
	_ = exceeded(t, podB.Check(bg, id))
}

func TestMeterQuotaOfAMonthThatEndedIsFlushedToThatMonth(t *testing.T) {
	t.Parallel()
	clock := newClock(time.Date(2026, time.October, 31, 23, 59, 59, 0, time.UTC))
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 100})
	m := testMeter(r, newBackend(shared), clock, nil)

	for i := 0; i < 3; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	clock.Set(time.Date(2026, time.November, 1, 0, 0, 1, 0, time.UTC))
	for i := 0; i < 2; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	require.NoError(t, m.SyncNow(bg))

	assert.EqualValues(t, 3, shared.total("t1", domain.KindQuota, "2026-10"), "billing for October is not lost at the boundary")
	assert.EqualValues(t, 2, shared.total("t1", domain.KindQuota, "2026-11"))
}

// A gateway that is not metered (no tenant, or no caps at all: OSS) is let
// through and leaves nothing behind: no counter, no sync work, no fail-open
// metric. Any other lookup failure fails open and is counted.
func TestMeterUnmeteredGatewayLeavesNoCounterAndLookupFailuresFailOpen(t *testing.T) {
	read := captureMetrics(t)
	r := newResolver()
	backend := newBackend(newShared())
	m := testMeter(r, backend, newClock(midMonth), nil)

	for i := 0; i < 50; i++ {
		assert.NoError(t, m.Check(bg, ids.New[ids.GatewayKind]()), "unknown to the resolver = unmetered")
	}
	assert.EqualValues(t, 0, m.tracked(), "an unmetered gateway must not create a counter")
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 0, backend.calls.Load(), "nothing to sync")
	assert.EqualValues(t, 0, read("trustgate.ratelimit.fail_open"), "unmetered is not a failure")

	r.err = commonerrors.ErrNotFound
	assert.NoError(t, m.Check(bg, ids.New[ids.GatewayKind]()), "a gateway that vanished fails open, as before")
	r.err = errors.New("db down")
	assert.NoError(t, m.Check(bg, ids.New[ids.GatewayKind]()), "a failed entitlements lookup fails open")
	assert.EqualValues(t, 2, read("trustgate.ratelimit.fail_open"))
	assert.EqualValues(t, 0, m.tracked())
}

func TestMeterEvictsIdleTenantsButNeverOneWithUnsentUsage(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 10, QuotaPerMonth: 100})
	m := testMeter(r, newBackend(newShared()), clock, nil)

	require.NoError(t, m.Check(bg, id))
	clock.Advance(DefaultIdleEviction + time.Minute)
	require.NoError(t, m.SyncNow(bg)) // flushes the one unit; the tenant is idle but was not quiet
	assert.EqualValues(t, 1, m.tracked(), "usage that had not reached Redis keeps the tenant tracked")

	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 0, m.tracked(), "quiet and idle: evicted")

	require.NoError(t, m.Check(bg, id), "an evicted tenant starts again from the next request")
	assert.EqualValues(t, 1, m.tracked())
}

func TestMeterSyncFailureKeepsUsageForTheNextTick(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, backend, clock, nil)

	for i := 0; i < 3; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	backend.fail.Store(true)
	require.Error(t, m.SyncNow(bg))
	require.NoError(t, m.Check(bg, id), "requests keep being served while Redis is down")

	backend.fail.Store(false)
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 4, shared.total("t1", domain.KindQuota, "2026-10"), "nothing admitted during the outage is lost")
}

func TestMeterDropsUnsyncedUsageAfterTheRetentionAndCountsIt(t *testing.T) {
	read := captureMetrics(t)
	clock := newClock(midMonth)
	shared := newShared()
	backend := newBackend(shared)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, backend, clock, func(o *Options) { o.FailedRetention = 30 * time.Second })

	for i := 0; i < 5; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	backend.fail.Store(true)
	require.Error(t, m.SyncNow(bg)) // first failure: the clock starts here
	clock.Advance(29 * time.Second)
	require.Error(t, m.SyncNow(bg))
	assert.EqualValues(t, 0, read("trustgate.ratelimit.sync.dropped"), "still inside the retention")
	clock.Advance(2 * time.Second)
	require.Error(t, m.SyncNow(bg)) // 31 s after the first failure
	backend.fail.Store(false)
	require.NoError(t, m.SyncNow(bg))

	assert.EqualValues(t, 0, shared.total("t1", domain.KindQuota, "2026-10"), "the bounded retention dropped it")
	assert.EqualValues(t, 5, read("trustgate.ratelimit.sync.dropped"))
	assert.EqualValues(t, 3, read("trustgate.ratelimit.sync.errors"))
}

func TestMeterRecordsSyncDurationAndFailOpen(t *testing.T) {
	read := captureMetrics(t)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 100})
	m := testMeter(r, newBackend(newShared()), newClock(midMonth), nil)

	require.NoError(t, m.Check(bg, id))
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 1, read("trustgate.ratelimit.sync.duration"))
	assert.EqualValues(t, 1, read("trustgate.ratelimit.tracked_tenants"))

	r.err = errors.New("db down")
	require.NoError(t, m.Check(bg, id))
	assert.EqualValues(t, 1, read("trustgate.ratelimit.fail_open"))
}

func TestMeterConcurrentRequestsNeverAdmitPastTheCap(t *testing.T) {
	t.Parallel()
	clock := newClock(midMonth)
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 500, QuotaPerMonth: 0})
	m := testMeter(r, newBackend(newShared()), clock, nil)

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if m.Check(bg, id) == nil {
					mu.Lock()
					admitted++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 500, admitted)
}
