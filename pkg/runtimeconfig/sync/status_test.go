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

package configsync

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestSnapshotStatus_StartsNone(t *testing.T) {
	t.Parallel()

	status := NewSnapshotStatus(newFakeClock().Now)

	assert.Equal(t, SnapshotNone, status.Info().State)
	_, ok := status.Age()
	assert.False(t, ok)
}

func TestSnapshotStatus_Transitions(t *testing.T) {
	t.Parallel()

	t.Run("none to lkg to live", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock()
		status := NewSnapshotStatus(clock.Now)

		status.MarkLKG("v1", 90*time.Second)
		info := status.Info()
		assert.Equal(t, SnapshotLKG, info.State)
		assert.Equal(t, "v1", info.Version)
		age, ok := status.Age()
		require.True(t, ok)
		assert.Equal(t, 90*time.Second, age)

		clock.Advance(10 * time.Second)
		age, _ = status.Age()
		assert.Equal(t, 100*time.Second, age)

		status.MarkLive("v2")
		info = status.Info()
		assert.Equal(t, SnapshotLive, info.State)
		assert.Equal(t, "v2", info.Version)
		age, _ = status.Age()
		assert.Zero(t, age)

		clock.Advance(time.Minute)
		age, _ = status.Age()
		assert.Equal(t, time.Minute, age)
	})

	t.Run("none to live", func(t *testing.T) {
		t.Parallel()
		status := NewSnapshotStatus(newFakeClock().Now)
		status.MarkLive("v1")
		assert.Equal(t, SnapshotLive, status.Info().State)
	})

	t.Run("confirm promotes only lkg", func(t *testing.T) {
		t.Parallel()
		clock := newFakeClock()
		status := NewSnapshotStatus(clock.Now)

		status.ConfirmLive()
		assert.Equal(t, SnapshotNone, status.Info().State)

		status.MarkLKG("v1", time.Hour)
		status.ConfirmLive()
		info := status.Info()
		assert.Equal(t, SnapshotLive, info.State)
		assert.Equal(t, "v1", info.Version)
		age, _ := status.Age()
		assert.Zero(t, age)
	})
}

func newStatusWorker(t *testing.T, fetcher *fakeFetcher, lkg *LKGStore[string], status *SnapshotStatus) (*Worker[string], ConfigStore[string]) {
	t.Helper()
	store := NewMemoryStore[string]()
	return NewWorker[string](fetcher, store, &fakeTransport{}, lkg, stringCodec{}, nil, WorkerConfig{},
		WithStatus[string](status)), store
}

func persistedLKG(t *testing.T, payload string) *LKGStore[string] {
	t.Helper()
	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	codec := stringCodec{}
	lkg := NewLKGStore[string](crypto, codec, filepath.Join(t.TempDir(), "lkg.enc"))
	raw, err := codec.Encode(payload)
	require.NoError(t, err)
	require.NoError(t, lkg.Persist(&Versioned[string]{Version: codec.Version(raw), Snapshot: payload, Raw: raw}))
	return lkg
}

func TestWorker_StatusRestoreLKGReportsLKG(t *testing.T) {
	t.Parallel()

	status := NewSnapshotStatus(nil)
	worker, store := newStatusWorker(t, &fakeFetcher{}, persistedLKG(t, "from-disk"), status)

	assert.Equal(t, SnapshotNone, status.Info().State)
	worker.restoreLKG()

	info := status.Info()
	assert.Equal(t, SnapshotLKG, info.State)
	assert.Equal(t, store.Version(), info.Version)
	assert.Same(t, status, worker.Status())
}

func TestWorker_StatusCorruptLKGStaysNone(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "lkg.enc")
	require.NoError(t, writeCorrupt(path))
	status := NewSnapshotStatus(nil)
	worker, _ := newStatusWorker(t, &fakeFetcher{}, NewLKGStore[string](crypto, stringCodec{}, path), status)

	worker.restoreLKG()

	assert.Equal(t, SnapshotNone, status.Info().State)
}

func TestWorker_StatusConvergeReportsLive(t *testing.T) {
	t.Parallel()

	codec := stringCodec{}
	raw := []byte("fresh")
	fetcher := &fakeFetcher{results: []fetchResult{{raw: raw, version: codec.Version(raw)}}}
	status := NewSnapshotStatus(nil)
	worker, _ := newStatusWorker(t, fetcher, nil, status)

	require.NoError(t, worker.Converge(context.Background()))

	info := status.Info()
	assert.Equal(t, SnapshotLive, info.State)
	assert.Equal(t, codec.Version(raw), info.Version)
}

func TestWorker_StatusLKGThenLiveOnConverge(t *testing.T) {
	t.Parallel()

	codec := stringCodec{}
	raw := []byte("fresh")
	fetcher := &fakeFetcher{results: []fetchResult{{raw: raw, version: codec.Version(raw)}}}
	status := NewSnapshotStatus(nil)
	worker, _ := newStatusWorker(t, fetcher, persistedLKG(t, "from-disk"), status)

	worker.restoreLKG()
	require.Equal(t, SnapshotLKG, status.Info().State)
	require.NoError(t, worker.Converge(context.Background()))

	info := status.Info()
	assert.Equal(t, SnapshotLive, info.State)
	assert.Equal(t, codec.Version(raw), info.Version)
}

func TestWorker_StatusNotModifiedConfirmsRestoredLKG(t *testing.T) {
	t.Parallel()

	fetcher := &fakeFetcher{results: []fetchResult{{notModified: true}}}
	status := NewSnapshotStatus(nil)
	worker, store := newStatusWorker(t, fetcher, persistedLKG(t, "from-disk"), status)

	worker.restoreLKG()
	require.NoError(t, worker.Converge(context.Background()))

	info := status.Info()
	assert.Equal(t, SnapshotLive, info.State)
	assert.Equal(t, store.Version(), info.Version)
}

func TestWorker_StatusFailedConvergeKeepsLKG(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result fetchResult
	}{
		{name: "fetch error", result: fetchResult{err: errors.New("control plane down")}},
		{name: "integrity mismatch", result: fetchResult{raw: []byte("tampered"), version: "not-the-sha"}},
		{name: "missing version", result: fetchResult{raw: []byte("x")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status := NewSnapshotStatus(nil)
			worker, store := newStatusWorker(t, &fakeFetcher{results: []fetchResult{tt.result}}, persistedLKG(t, "from-disk"), status)
			worker.restoreLKG()
			lkgVersion := store.Version()

			require.Error(t, worker.Converge(context.Background()))

			info := status.Info()
			assert.Equal(t, SnapshotLKG, info.State)
			assert.Equal(t, lkgVersion, info.Version)
		})
	}
}

func TestReadinessCheck_StaysRedWhileStatusNone(t *testing.T) {
	t.Parallel()

	status := NewSnapshotStatus(nil)
	worker, store := newStatusWorker(t, &fakeFetcher{results: []fetchResult{{err: errors.New("down")}}}, nil, status)
	check := ReadinessCheck[string](store)

	require.Error(t, worker.Converge(context.Background()))

	require.ErrorIs(t, check(context.Background()), ErrNotReady)
	assert.Equal(t, SnapshotNone, status.Info().State)
}

type gaugeReading struct {
	loaded int64
	source map[string]int64
	age    *float64
}

func readGauges(t *testing.T, status *SnapshotStatus) gaugeReading {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	require.NoError(t, RegisterSnapshotGauges(provider.Meter("test"), status))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	out := gaugeReading{source: map[string]int64{}}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					switch m.Name {
					case SnapshotLoadedMetric:
						out.loaded = dp.Value
					case SnapshotSourceMetric:
						v, _ := dp.Attributes.Value(attribute.Key("source"))
						out.source[v.AsString()] = dp.Value
					}
				}
			case metricdata.Gauge[float64]:
				for _, dp := range data.DataPoints {
					if m.Name == SnapshotAgeMetric {
						v := dp.Value
						out.age = &v
					}
				}
			}
		}
	}
	return out
}

func TestRegisterSnapshotGauges_ReflectEachState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		prepare    func(*SnapshotStatus, *fakeClock)
		wantLoaded int64
		wantSource map[string]int64
		wantAge    *float64
	}{
		{
			name:       "none",
			prepare:    func(*SnapshotStatus, *fakeClock) {},
			wantLoaded: 0,
			wantSource: map[string]int64{"none": 1, "lkg": 0, "live": 0},
		},
		{
			name: "lkg",
			prepare: func(s *SnapshotStatus, c *fakeClock) {
				s.MarkLKG("v1", 2*time.Minute)
				c.Advance(30 * time.Second)
			},
			wantLoaded: 1,
			wantSource: map[string]int64{"none": 0, "lkg": 1, "live": 0},
			wantAge:    ptr(150.0),
		},
		{
			name: "live",
			prepare: func(s *SnapshotStatus, c *fakeClock) {
				s.MarkLive("v2")
				c.Advance(45 * time.Second)
			},
			wantLoaded: 1,
			wantSource: map[string]int64{"none": 0, "lkg": 0, "live": 1},
			wantAge:    ptr(45.0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clock := newFakeClock()
			status := NewSnapshotStatus(clock.Now)
			tt.prepare(status, clock)

			got := readGauges(t, status)

			assert.Equal(t, tt.wantLoaded, got.loaded)
			assert.Equal(t, tt.wantSource, got.source)
			if tt.wantAge == nil {
				assert.Nil(t, got.age, "age must be absent while no snapshot is loaded")
				return
			}
			require.NotNil(t, got.age)
			assert.InDelta(t, *tt.wantAge, *got.age, 0.001)
		})
	}
}

func ptr[T any](v T) *T { return &v }
