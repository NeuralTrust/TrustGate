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
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// midMonth is a stable instant well inside a minute and a month.
var midMonth = time.Date(2026, time.October, 15, 12, 0, 10, 0, time.UTC)

// stubResolver maps gateways to a subject and caps; the caps can change under a
// running meter, as a tier change does.
type stubResolver struct {
	mu     sync.Mutex
	byID   map[ids.GatewayID]Resolved
	err    error
	called atomic.Int64
}

func newResolver() *stubResolver { return &stubResolver{byID: map[ids.GatewayID]Resolved{}} }

func (r *stubResolver) set(id ids.GatewayID, subject string, limits domain.Limits) {
	r.mu.Lock()
	r.byID[id] = Resolved{Subject: subject, Limits: limits}
	r.mu.Unlock()
}

func (r *stubResolver) Resolve(_ context.Context, id ids.GatewayID) (Resolved, error) {
	r.called.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Resolved{}, r.err
	}
	got, ok := r.byID[id]
	if !ok {
		return Resolved{}, ErrUnmetered
	}
	return got, nil
}

// sharedCounters is the Redis stand-in several meters (pods) sync against.
type sharedCounters struct {
	mu     sync.Mutex
	totals map[string]int64
	tokens map[string]bool
}

func newShared() *sharedCounters {
	return &sharedCounters{totals: map[string]int64{}, tokens: map[string]bool{}}
}

func (s *sharedCounters) total(subject string, kind domain.CounterKind, window string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totals[fmt.Sprintf("%s|%s|%s", subject, kind, window)]
}

// memBackend is a SyncBackend over sharedCounters that can be told to fail or
// to take its time.
type memBackend struct {
	shared *sharedCounters
	calls  atomic.Int64
	fail   atomic.Bool
	// poisoned, when set, is a subject whose item fails while the call itself
	// and every other item succeed, like one tenant's keys on a broken shard.
	poisoned atomic.Pointer[string]
	// block, when set, is waited on (or the context) before answering.
	block atomic.Pointer[chan struct{}]
	// blockIgnoresCtx makes block wait for its channel only, like a server that
	// is already working on the request when the client gives up.
	blockIgnoresCtx atomic.Bool
	// lostReplies makes the next N calls apply the batch and then report a
	// timeout, which is what a reply lost on the wire looks like.
	lostReplies atomic.Int64
	// failIfCancelled makes a call that finds its context cancelled after
	// applying report that error, as a client cut short by shutdown does.
	failIfCancelled atomic.Bool
	// cancelledCalls counts calls whose context was already cancelled when they
	// were answered.
	cancelledCalls atomic.Int64
	// delay is how long each call takes, ignoring the context (a server that
	// is already working on the request).
	delay atomic.Int64
	// onCall, when set, runs at the start of each call with its number.
	onCall atomic.Pointer[func(n int64)]
}

func newBackend(shared *sharedCounters) *memBackend { return &memBackend{shared: shared} }

func (b *memBackend) Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error) {
	n := b.calls.Add(1)
	if f := b.onCall.Load(); f != nil {
		(*f)(n)
	}
	if d := b.delay.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	if ch := b.block.Load(); ch != nil {
		if b.blockIgnoresCtx.Load() {
			<-*ch
		} else {
			select {
			case <-*ch:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	if b.fail.Load() {
		return nil, errors.New("redis down")
	}
	b.shared.mu.Lock()
	defer b.shared.mu.Unlock()
	out := make([]domain.SyncResult, len(items))
	for i, item := range items {
		if p := b.poisoned.Load(); p != nil && *p == item.Subject {
			out[i] = domain.SyncResult{Err: errors.New("poisoned tenant")}
			continue
		}
		// Like the Redis script: a token already seen means the bumps were
		// applied, so only the totals are reported.
		apply := true
		if item.Token != "" {
			tk := item.Subject + "|" + item.Token
			apply = !b.shared.tokens[tk]
			b.shared.tokens[tk] = true
		}
		totals := make([]int64, len(item.Bumps))
		for j, bump := range item.Bumps {
			key := fmt.Sprintf("%s|%s|%s", item.Subject, bump.Kind, bump.Window)
			if apply {
				b.shared.totals[key] += bump.Delta
			}
			totals[j] = b.shared.totals[key]
		}
		out[i] = domain.SyncResult{Totals: totals}
	}
	if ctx.Err() != nil {
		b.cancelledCalls.Add(1)
		if b.failIfCancelled.Load() {
			return nil, ctx.Err()
		}
	}
	if b.lostReplies.Load() > 0 {
		b.lostReplies.Add(-1)
		return nil, context.DeadlineExceeded
	}
	return out, nil
}

// testMeter builds a meter over the stubs with the clock fixed.
func testMeter(r GatewayTierLoader, b SyncBackend, clock *fakeClock, mod func(*Options)) *Meter {
	opts := Options{Now: clock.Now}
	if mod != nil {
		mod(&opts)
	}
	return NewMeter(r, b, opts, discardLogger())
}

// readMetric sets up an in-memory metrics pipeline for the test and returns a
// function reading the sum of a counter by name. The global provider is
// process-wide, so tests that use it must not run in parallel.
func captureMetrics(t *testing.T) func(name string) int64 {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		otel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})
	return func(name string) int64 {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("collect metrics: %v", err)
		}
		var sum int64
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != name {
					continue
				}
				switch d := m.Data.(type) {
				case metricdata.Sum[int64]:
					for _, dp := range d.DataPoints {
						sum += dp.Value
					}
				case metricdata.Gauge[int64]:
					for _, dp := range d.DataPoints {
						sum += dp.Value
					}
				case metricdata.Histogram[float64]:
					for _, dp := range d.DataPoints {
						sum += int64(dp.Count)
					}
				}
			}
		}
		return sum
	}
}
