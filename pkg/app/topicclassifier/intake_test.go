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

package topicclassifier

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeQueue struct {
	mu       sync.Mutex
	requests []topic.Request
	enqueued chan topic.Request
	enqueue  func(ctx context.Context, req topic.Request) error
}

func newFakeQueue() *fakeQueue {
	return &fakeQueue{enqueued: make(chan topic.Request, 64)}
}

func (q *fakeQueue) Enqueue(ctx context.Context, req topic.Request) error {
	var err error
	if q.enqueue != nil {
		err = q.enqueue(ctx, req)
	}
	if err == nil {
		q.mu.Lock()
		q.requests = append(q.requests, req)
		q.mu.Unlock()
	}
	q.enqueued <- req
	return err
}

func (q *fakeQueue) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.requests)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func enabledConfig() *topic.Config {
	threshold := 0.5
	return &topic.Config{
		Enabled:       true,
		Topics:        []topic.Topic{{Name: "billing", Definition: "refunds and invoices"}},
		Threshold:     &threshold,
		MessageWindow: 2,
	}
}

func candidate(cfg *topic.Config) Candidate {
	return Candidate{
		GatewayID:    "gw-1",
		ConsumerID:   "consumer-1",
		TraceID:      "trace-1",
		SourceFormat: adapter.FormatOpenAI,
		Body:         []byte(openAIConversation),
		Config:       cfg,
		ReceivedAt:   time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC),
	}
}

func startIntake(t *testing.T, q Queue, cfg IntakeConfig) *intake {
	t.Helper()
	in := newIntake(quietLogger(), adapter.NewRegistry(), q, nil, cfg)
	in.Start()
	t.Cleanup(func() { _ = in.Shutdown(context.Background()) })
	return in
}

func waitEnqueued(t *testing.T, q *fakeQueue) topic.Request {
	t.Helper()
	select {
	case req := <-q.enqueued:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an enqueue")
		return topic.Request{}
	}
}

func TestIntake_EnqueuesTheBuiltRequest(t *testing.T) {
	t.Parallel()
	q := newFakeQueue()
	in := startIntake(t, q, IntakeConfig{})

	cfg := enabledConfig()
	require.True(t, in.Submit(candidate(cfg)))
	req := waitEnqueued(t, q)

	assert.Equal(t, "gw-1", req.GatewayID)
	assert.Equal(t, "consumer-1", req.ConsumerID)
	assert.Equal(t, "trace-1", req.TraceID)
	assert.Equal(t, "INV-42\nyes, do it", req.Text)
	assert.Equal(t, topic.HashText(req.Text), req.TextHash)
	assert.Equal(t, topic.CatalogHash(cfg.Topics), req.CatalogHash)
	require.NotNil(t, req.Threshold)
	assert.InDelta(t, 0.5, *req.Threshold, 1e-9)
}

func TestIntake_DropsWithoutEnqueueing(t *testing.T) {
	t.Parallel()

	noUserText := candidate(enabledConfig())
	noUserText.Body = []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"only system"}]}`)

	tests := []struct {
		name string
		cand Candidate
	}{
		{name: "disabled config", cand: candidate(&topic.Config{Enabled: false, Topics: enabledConfig().Topics})},
		{name: "nil config", cand: candidate(nil)},
		{name: "no user text", cand: noUserText},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			q := newFakeQueue()
			in := newIntake(quietLogger(), adapter.NewRegistry(), q, nil, IntakeConfig{})
			in.Start()
			require.True(t, in.Submit(tt.cand))
			require.NoError(t, in.Shutdown(context.Background()))
			assert.Zero(t, q.count())
		})
	}
}

func TestIntake_BoundsBufferedBytes(t *testing.T) {
	t.Parallel()
	body := len(candidate(enabledConfig()).Body)
	in := newIntake(quietLogger(), adapter.NewRegistry(), newFakeQueue(), nil, IntakeConfig{QueueSize: 100, MaxBufferBytes: int64(2 * body)})

	require.True(t, in.Submit(candidate(enabledConfig())))
	require.True(t, in.Submit(candidate(enabledConfig())))
	assert.False(t, in.Submit(candidate(enabledConfig())), "the byte budget binds before the slot count")
	assert.Equal(t, int64(2*body), in.buffered.Load(), "a refused candidate releases what it reserved")

	in.Start()
	require.NoError(t, in.Shutdown(context.Background()))
	assert.Zero(t, in.buffered.Load(), "queued candidates release their bytes")
}

func TestIntake_SubmitNeverBlocks(t *testing.T) {
	t.Parallel()
	in := newIntake(quietLogger(), adapter.NewRegistry(), newFakeQueue(), nil, IntakeConfig{QueueSize: 1})

	require.True(t, in.Submit(candidate(enabledConfig())))
	done := make(chan bool, 1)
	go func() { done <- in.Submit(candidate(enabledConfig())) }()
	select {
	case accepted := <-done:
		assert.False(t, accepted, "a full buffer must drop, not accept")
	case <-time.After(time.Second):
		t.Fatal("Submit blocked on a full buffer")
	}
}

func TestIntake_ShutdownDrainsBufferedCandidates(t *testing.T) {
	t.Parallel()
	q := newFakeQueue()
	in := newIntake(quietLogger(), adapter.NewRegistry(), q, nil, IntakeConfig{QueueSize: 8})

	for range 5 {
		require.True(t, in.Submit(candidate(enabledConfig())))
	}
	in.Start()
	require.NoError(t, in.Shutdown(context.Background()))

	assert.Equal(t, 5, q.count())
	assert.False(t, in.Submit(candidate(enabledConfig())), "a shut down intake must refuse candidates")
	require.NoError(t, in.Shutdown(context.Background()), "a second Shutdown is a no-op")
}

func TestIntake_ShutdownWithoutStart(t *testing.T) {
	t.Parallel()
	in := newIntake(quietLogger(), adapter.NewRegistry(), newFakeQueue(), nil, IntakeConfig{})
	require.NoError(t, in.Shutdown(context.Background()))
	assert.False(t, in.Submit(candidate(enabledConfig())))
}

func TestIntake_ShutdownDeadlineCancelsInFlightEnqueue(t *testing.T) {
	t.Parallel()
	q := newFakeQueue()
	started := make(chan struct{})
	var cancelled bool
	var once sync.Once
	q.enqueue = func(ctx context.Context, _ topic.Request) error {
		once.Do(func() { close(started) })
		<-ctx.Done()
		cancelled = true
		return ctx.Err()
	}
	in := newIntake(quietLogger(), adapter.NewRegistry(), q, nil, IntakeConfig{Workers: 1, EnqueueTimeout: time.Minute})
	in.Start()
	require.True(t, in.Submit(candidate(enabledConfig())))
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := in.Shutdown(ctx)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, cancelled, "the in-flight enqueue must see its context cancelled")
}

func TestIntake_SurvivesEnqueueFailuresAndPanics(t *testing.T) {
	t.Parallel()
	q := newFakeQueue()
	var calls int
	var mu sync.Mutex
	q.enqueue = func(context.Context, topic.Request) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		switch calls {
		case 1:
			return errors.New("redis unavailable")
		case 2:
			panic("boom")
		default:
			return nil
		}
	}
	in := startIntake(t, q, IntakeConfig{Workers: 1})

	for range 3 {
		require.True(t, in.Submit(candidate(enabledConfig())))
	}
	waitEnqueued(t, q)
	waitEnqueued(t, q)
	require.Eventually(t, func() bool { return q.count() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the worker must keep going after an error and a panic")
}
