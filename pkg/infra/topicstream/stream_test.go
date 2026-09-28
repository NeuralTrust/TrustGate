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

package topicstream

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

type harness struct {
	mr     *miniredis.Miniredis
	client *redis.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	mr.SetTime(t0)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return &harness{mr: mr, client: client}
}

func (h *harness) stream(t *testing.T, consumer string, cfg Config) *Stream {
	t.Helper()
	s := New(h.client, cfg)
	s.consumer = consumer
	s.now = func() time.Time { return t0 }
	require.NoError(t, s.EnsureGroup(context.Background()))
	return s
}

func request(gateway, text string) topic.Request {
	return topic.NewRequest(topic.RequestParams{
		GatewayID: gateway,
		TraceID:   "trace-" + text,
		Text:      text,
		Config:    &topic.Config{Enabled: true, Topics: []topic.Topic{{Name: "billing", Definition: "refunds"}}},
	})
}

func (h *harness) xlen(t *testing.T) int64 {
	t.Helper()
	n, err := h.client.XLen(context.Background(), streamKey).Result()
	require.NoError(t, err)
	return n
}

func TestStream_EnsureGroupIsIdempotent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	require.NoError(t, s.EnsureGroup(context.Background()))
}

func TestStream_EnqueueAndRead(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	ctx := context.Background()

	want := request("gw-1", "where is my refund")
	require.NoError(t, s.Enqueue(ctx, want))

	got, err := s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.False(t, got[0].Invalid)
	assert.Equal(t, int64(1), got[0].Deliveries)
	assert.Equal(t, want.TraceID, got[0].Request.TraceID)
	assert.Equal(t, want.TextHash, got[0].Request.TextHash)
	assert.Equal(t, want.Topics, got[0].Request.Topics)

	again, err := s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)
	assert.Empty(t, again, "an entry already handed out must not be read again")
}

func TestStream_OneConsumerPerEntry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	a := h.stream(t, "a", Config{})
	b := h.stream(t, "b", Config{})
	ctx := context.Background()

	for i := range 4 {
		require.NoError(t, a.Enqueue(ctx, request("gw-1", fmt.Sprintf("text %d", i))))
	}
	fromA, err := a.Read(ctx, 2, 10*time.Millisecond)
	require.NoError(t, err)
	fromB, err := b.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, d := range append(fromA, fromB...) {
		assert.False(t, seen[d.ID], "entry %s handed to two consumers", d.ID)
		seen[d.ID] = true
	}
	assert.Len(t, seen, 4)
}

func TestStream_GatewayQuota(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{GatewayQuotaPerSecond: 2})
	ctx := context.Background()

	require.NoError(t, s.Enqueue(ctx, request("noisy", "1")))
	require.NoError(t, s.Enqueue(ctx, request("noisy", "2")))
	require.ErrorIs(t, s.Enqueue(ctx, request("noisy", "3")), topic.ErrQuotaExceeded)
	require.NoError(t, s.Enqueue(ctx, request("quiet", "1")), "another gateway keeps its own share")
	assert.Equal(t, int64(3), h.xlen(t))

	h.mr.FastForward(quotaWindow + time.Millisecond)
	require.NoError(t, s.Enqueue(ctx, request("noisy", "4")), "the quota resets with the window")
}

func TestStream_QuotaDisabled(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{GatewayQuotaPerSecond: 0})
	for i := range 20 {
		require.NoError(t, s.Enqueue(context.Background(), request("gw", fmt.Sprint(i))))
	}
	assert.Equal(t, int64(20), h.xlen(t))
}

func TestStream_MaxLen(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{MaxLen: 3})
	for i := range 10 {
		require.NoError(t, s.Enqueue(context.Background(), request("gw", fmt.Sprint(i))))
	}
	assert.LessOrEqual(t, h.xlen(t), int64(3))
}

func TestStream_RetentionTrimsOldEntries(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{Retention: time.Minute})
	ctx := context.Background()

	require.NoError(t, s.Enqueue(ctx, request("gw", "old")))

	later := t0.Add(2 * time.Minute)
	h.mr.SetTime(later)
	s.now = func() time.Time { return later }
	require.NoError(t, s.Enqueue(ctx, request("gw", "new")))

	got, err := s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)
	require.Len(t, got, 1, "an entry past the retention must be trimmed")
	assert.Equal(t, "trace-new", got[0].Request.TraceID)
}

func TestStream_AckAndReclaim(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	dead := h.stream(t, "dead-pod", Config{})
	alive := h.stream(t, "alive-pod", Config{})
	ctx := context.Background()

	require.NoError(t, dead.Enqueue(ctx, request("gw", "left behind")))
	require.NoError(t, dead.Enqueue(ctx, request("gw", "finished")))
	read, err := dead.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)
	require.Len(t, read, 2)
	require.NoError(t, dead.Ack(ctx, read[1].ID))

	h.mr.SetTime(t0.Add(time.Minute))
	reclaimed, err := alive.Reclaim(ctx, 30*time.Second, 10)
	require.NoError(t, err)
	require.Len(t, reclaimed, 1, "only the unacknowledged entry is reclaimed")
	assert.Equal(t, read[0].ID, reclaimed[0].ID)
	assert.Equal(t, "trace-left behind", reclaimed[0].Request.TraceID)
	assert.Equal(t, int64(2), reclaimed[0].Deliveries)

	require.NoError(t, alive.Ack(ctx, reclaimed[0].ID))
	none, err := alive.Reclaim(ctx, 0, 10)
	require.NoError(t, err)
	assert.Empty(t, none)
	require.NoError(t, alive.Ack(ctx))
}

func TestStream_ReclaimRespectsMinIdle(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	ctx := context.Background()

	require.NoError(t, s.Enqueue(ctx, request("gw", "busy")))
	_, err := s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)

	reclaimed, err := s.Reclaim(ctx, time.Hour, 10)
	require.NoError(t, err)
	assert.Empty(t, reclaimed, "an entry still being worked on must not be taken over")
}

func TestStream_InvalidEntry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	ctx := context.Background()

	require.NoError(t, h.client.XAdd(ctx, &redis.XAddArgs{Stream: streamKey, Values: map[string]any{fieldRequest: "{not json"}}).Err())
	require.NoError(t, h.client.XAdd(ctx, &redis.XAddArgs{Stream: streamKey, Values: map[string]any{"other": "x"}}).Err())

	got, err := s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.True(t, got[0].Invalid)
	assert.True(t, got[1].Invalid)
}

func TestStream_ReadTimesOutEmpty(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	got, err := s.Read(context.Background(), 10, 10*time.Millisecond)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestStream_Stats(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	ctx := context.Background()

	for i := range 3 {
		require.NoError(t, s.Enqueue(ctx, request("gw", fmt.Sprint(i))))
	}
	read, err := s.Read(ctx, 2, 10*time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, s.Ack(ctx, read[0].ID))

	length, pending, err := s.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), length)
	assert.Equal(t, int64(1), pending, "handed out and not acknowledged")
}

func TestStream_StatsBeforeTheGroupExists(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := New(h.client, Config{})
	length, pending, err := s.Stats(context.Background())
	require.NoError(t, err)
	assert.Zero(t, length)
	assert.Zero(t, pending)
}

func TestStream_RecreatesAMissingGroup(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	s := h.stream(t, "a", Config{})
	ctx := context.Background()

	h.mr.FlushAll()
	got, err := s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err, "a lost group is recreated, not reported forever")
	assert.Empty(t, got)
	_, err = s.Reclaim(ctx, 0, 10)
	require.NoError(t, err)

	require.NoError(t, s.Enqueue(ctx, request("gw", "after the flush")))
	got, err = s.Read(ctx, 10, 10*time.Millisecond)
	require.NoError(t, err)
	require.Len(t, got, 1)
}
