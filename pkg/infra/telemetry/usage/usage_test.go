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

package usage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

type memExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
	fail    error
	block   chan struct{}
}

func (m *memExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if m.block != nil {
		select {
		case <-m.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail != nil {
		return m.fail
	}
	for _, r := range records {
		m.records = append(m.records, r.Clone())
	}
	return nil
}

func (m *memExporter) Shutdown(context.Context) error   { return nil }
func (m *memExporter) ForceFlush(context.Context) error { return nil }

func (m *memExporter) all() []sdklog.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sdklog.Record(nil), m.records...)
}

type outcomeCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *outcomeCounter) Outcome(outcome string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[string]int)
	}
	c.counts[outcome] += n
}

func (c *outcomeCounter) get(outcome string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[outcome]
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func attrs(rec sdklog.Record) map[string]attribute.Value {
	out := make(map[string]attribute.Value)
	rec.WalkAttributes(func(kv attribute.KeyValue) bool {
		out[string(kv.Key)] = kv.Value
		return true
	})
	return out
}

func sampleRecord(t *testing.T) usagedomain.Record {
	t.Helper()
	r, err := usagedomain.NewRecord(usagedomain.Record{
		EventID:                usagedomain.RequestEventID("4bf92f35-77b3-4da6-a3ce-929d0e0e4736"),
		TenantID:               "team_8f2c",
		OccurredOn:             time.Date(2026, 10, 20, 8, 5, 25, 123000000, time.UTC),
		TraceID:                "4bf92f35-77b3-4da6-a3ce-929d0e0e4736",
		GatewayID:              "gw_51a",
		Requests:               1,
		SmartRoutingExecutions: 1,
	})
	require.NoError(t, err)
	return r
}

func TestEmitter_MapsRecordToContract(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	counter := &outcomeCounter{}
	e := newEmitter(mem, 16, counter, discardLogger())
	e.Emit(context.Background(), sampleRecord(t))
	e.Close()

	records := mem.all()
	require.Len(t, records, 1)
	rec := records[0]
	assert.Equal(t, EventName, rec.EventName())
	assert.Equal(t, time.Date(2026, 10, 20, 8, 5, 25, 123000000, time.UTC), rec.Timestamp())

	got := attrs(rec)
	assert.Equal(t, "1", got["usage.schema_version"].AsString())
	assert.Equal(t, "trustgate:4bf92f35-77b3-4da6-a3ce-929d0e0e4736", got["usage.event_id"].AsString())
	assert.Equal(t, "trustgate", got["usage.product"].AsString())
	assert.Equal(t, "team_8f2c", got["usage.tenant_id"].AsString())
	assert.Equal(t, "2026-10-20T08:05:25.123Z", got["usage.occurred_on"].AsString())
	assert.Equal(t, "4bf92f35-77b3-4da6-a3ce-929d0e0e4736", got["usage.trace_id"].AsString())
	assert.Equal(t, "gw_51a", got["usage.gateway_id"].AsString())
	assert.Equal(t, int64(1), got["usage.requests"].AsInt64())
	assert.Equal(t, int64(1), got["usage.smart_routing_executions"].AsInt64())
	assert.NotContains(t, got, "usage.consumer_id")
	assert.NotContains(t, got, "usage.topic_classification_chars")
	for key := range got {
		assert.Regexp(t, `^usage\.`, key)
	}
	assert.Equal(t, 1, counter.get(usagedomain.OutcomeEmitted))
}

func TestEmitter_FullQueueDropsWithoutBlocking(t *testing.T) {
	t.Parallel()
	mem := &memExporter{block: make(chan struct{})}
	counter := &outcomeCounter{}
	e := newEmitter(mem, 2, counter, discardLogger())
	record := sampleRecord(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range defaultBatchSize + 100 {
			e.Emit(context.Background(), record)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a full queue")
	}
	assert.Positive(t, counter.get(usagedomain.OutcomeDropped))

	close(mem.block)
	e.Close()
	total := counter.get(usagedomain.OutcomeEmitted) + counter.get(usagedomain.OutcomeDropped)
	assert.Equal(t, defaultBatchSize+100, total)
	assert.Len(t, mem.all(), counter.get(usagedomain.OutcomeEmitted))
}

func TestEmitter_CountsFailedExports(t *testing.T) {
	t.Parallel()
	mem := &memExporter{fail: errors.New("collector unavailable")}
	counter := &outcomeCounter{}
	e := newEmitter(mem, 16, counter, discardLogger())
	for range 3 {
		e.Emit(context.Background(), sampleRecord(t))
	}
	e.Close()
	assert.Equal(t, 3, counter.get(usagedomain.OutcomeExportFailed))
	assert.Zero(t, counter.get(usagedomain.OutcomeEmitted))
}

func TestEmitter_CloseDrainsQueue(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	counter := &outcomeCounter{}
	e := newEmitter(mem, 1024, counter, discardLogger())
	for range 700 {
		e.Emit(context.Background(), sampleRecord(t))
	}
	e.Close()
	assert.Len(t, mem.all(), 700)

	e.Emit(context.Background(), sampleRecord(t))
	e.Close()
	assert.Len(t, mem.all(), 700)
}

func TestEmitter_CloseCountsRecordsItCannotExportInTime(t *testing.T) {
	t.Parallel()
	mem := &memExporter{block: make(chan struct{})}
	counter := &outcomeCounter{}
	e := newEmitter(mem, 16, counter, discardLogger())
	for range 5 {
		e.Emit(context.Background(), sampleRecord(t))
	}
	start := time.Now()
	e.closeWithin(50 * time.Millisecond)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Eventually(t, func() bool {
		return counter.get(usagedomain.OutcomeExportFailed) == 5
	}, 5*time.Second, 10*time.Millisecond)
	assert.Zero(t, counter.get(usagedomain.OutcomeEmitted))
}

func TestEmitter_CancelledContextStillQueues(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	e := newEmitter(mem, 16, &outcomeCounter{}, discardLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.Emit(ctx, sampleRecord(t))
	e.Close()
	assert.Len(t, mem.all(), 1)
}

func TestNew_DisabledIsNoop(t *testing.T) {
	t.Parallel()
	e, err := New(context.Background(), nil, &outcomeCounter{}, discardLogger())
	require.NoError(t, err)
	assert.False(t, e.Enabled())
	e.Emit(context.Background(), sampleRecord(t))
	e.Close()
}
