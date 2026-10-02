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
	"fmt"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// droppedByReason reads trustgate.ratelimit.sync.dropped for one reason. The
// global provider is process-wide: callers must not run in parallel.
func droppedByReason(t *testing.T) func(reason string) int64 {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})
	return func(reason string) int64 {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		var sum int64
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				d, ok := m.Data.(metricdata.Sum[int64])
				if !ok || m.Name != "trustgate.ratelimit.sync.dropped" {
					continue
				}
				for _, dp := range d.DataPoints {
					if v, ok := dp.Attributes.Value("reason"); ok && v.AsString() == reason {
						sum += dp.Value
					}
				}
			}
		}
		return sum
	}
}

// sixTenants builds a meter over six tenants that each admitted two units, with
// two tenants per chunk: three chunks.
func sixTenants(t *testing.T, backend SyncBackend, mod func(*Options)) *Meter {
	t.Helper()
	r := newResolver()
	m := testMeter(r, backend, newClock(midMonth), func(o *Options) {
		o.MaxBatch = 2
		o.SyncTimeout = 5 * time.Second
		o.DisableKick = true
		if mod != nil {
			mod(o)
		}
	})
	for i := 0; i < 6; i++ {
		id := ids.New[ids.GatewayKind]()
		r.set(id, fmt.Sprintf("t%d", i), domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000})
		for j := 0; j < 2; j++ {
			require.NoError(t, m.Check(bg, id))
		}
	}
	return m
}

func sentTotal(shared *sharedCounters) int64 {
	var sent int64
	for i := 0; i < 6; i++ {
		sent += shared.total(fmt.Sprintf("t%d", i), domain.KindQuota, "2026-10")
	}
	return sent
}

// The shutdown flush stops starting chunks once its context is done, but never
// cancels the chunk on the wire; what it did not send is counted as dropped.
func TestFlushStopsStartingChunksButFinishesTheOneInFlight(t *testing.T) {
	read := droppedByReason(t)
	shared := newShared()
	backend := newBackend(shared)
	backend.failIfCancelled.Store(true)
	backend.delay.Store(int64(50 * time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The flush's deadline expires while the first chunk is on the wire.
	hook := func(n int64) {
		if n == 1 {
			cancel()
		}
	}
	backend.onCall.Store(&hook)
	m := sixTenants(t, backend, nil)

	err := m.sync(ctx, true)

	require.Error(t, err)
	assert.EqualValues(t, 1, backend.calls.Load(), "no chunk is started after the deadline")
	assert.Zero(t, backend.cancelledCalls.Load(), "the chunk on the wire was not cancelled")
	assert.EqualValues(t, 4, sentTotal(shared), "the in-flight chunk (two tenants) completed")
	assert.EqualValues(t, 8, read("shutdown"), "the four tenants left unsent are counted as dropped")
	assert.Zero(t, read("retention"))
}

// Through FlushTimeout itself: a flush that takes longer than the option stops
// after the chunk it was in.
func TestFlushTimeoutBoundsTheShutdownFlush(t *testing.T) {
	read := droppedByReason(t)
	backend := newBackend(newShared())
	backend.delay.Store(int64(300 * time.Millisecond))
	m := sixTenants(t, backend, func(o *Options) { o.FlushTimeout = 100 * time.Millisecond })

	start := time.Now()
	m.flushOnShutdown()

	assert.EqualValues(t, 1, backend.calls.Load(), "FlushTimeout ended the flush after the first chunk")
	assert.Less(t, time.Since(start), 900*time.Millisecond, "it did not go through all three chunks")
	assert.EqualValues(t, 8, read("shutdown"))
}

// Outside the shutdown flush, a sync cut short keeps what it did not send for
// the next round instead of dropping it.
func TestSyncCutShortKeepsUnsentUsageForTheNextRound(t *testing.T) {
	read := droppedByReason(t)
	shared := newShared()
	backend := newBackend(shared)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook := func(n int64) {
		if n == 1 {
			cancel()
		}
	}
	backend.onCall.Store(&hook)
	m := sixTenants(t, backend, nil)

	require.Error(t, m.sync(ctx, false))
	require.EqualValues(t, 1, backend.calls.Load())
	require.NoError(t, m.SyncNow(bg))

	assert.EqualValues(t, 12, sentTotal(shared), "nothing was lost")
	assert.Zero(t, read("shutdown"))
}
