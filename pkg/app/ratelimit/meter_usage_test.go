// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ratelimit

import (
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func usageEnforcing(on *atomic.Bool) func(*Options) {
	return func(o *Options) { o.UsageEnforcing = on.Load }
}

func TestMeterMonthlyQuotaYieldsToUsageSystem(t *testing.T) {
	t.Parallel()
	shared := newShared()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 2})
	var on atomic.Bool
	on.Store(true)
	m := testMeter(r, newBackend(shared), newClock(midMonth), usageEnforcing(&on))

	for i := 0; i < 5; i++ {
		require.NoError(t, m.Check(bg, id), "request %d past the monthly cap", i+1)
	}
	require.NoError(t, m.SyncNow(bg))
	assert.EqualValues(t, 5, shared.total("t1", domain.KindQuota, "2026-10"), "usage is still counted")
}

func TestMeterBurstStillRefusesWhileUsageSystemEnforces(t *testing.T) {
	t.Parallel()
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 2, QuotaPerMonth: 1000})
	var on atomic.Bool
	on.Store(true)
	m := testMeter(r, newBackend(newShared()), newClock(midMonth), usageEnforcing(&on))

	require.NoError(t, m.Check(bg, id))
	require.NoError(t, m.Check(bg, id))
	assert.Equal(t, ReasonBurst, exceeded(t, m.Check(bg, id)).Reason)
}

func TestMeterMonthlyQuotaReturnsWhenUsageSystemStops(t *testing.T) {
	t.Parallel()
	clock := newClock(time.Date(2026, time.October, 31, 23, 0, 0, 0, time.UTC))
	r, id := oneGateway("t1", domain.Limits{BurstPerMin: 100, QuotaPerMonth: 3})
	var on atomic.Bool
	on.Store(true)
	m := testMeter(r, newBackend(newShared()), clock, usageEnforcing(&on))

	for i := 0; i < 4; i++ {
		require.NoError(t, m.Check(bg, id))
	}
	on.Store(false)
	ex := exceeded(t, m.Check(bg, id))
	assert.Equal(t, ReasonQuota, ex.Reason, "the usage counted meanwhile counts against the cap")
	assert.Equal(t, 3, ex.Limit)
	assert.Equal(t, time.Hour, ex.RetryAfter)

	on.Store(true)
	require.NoError(t, m.Check(bg, id), "the flag is read on every request")
}
