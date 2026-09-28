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
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingRecorder struct {
	mu      sync.Mutex
	intake  map[string]int
	enqueue map[string]int
	results map[string]int
	calls   map[string]int
}

func newCountingRecorder() *countingRecorder {
	return &countingRecorder{intake: map[string]int{}, enqueue: map[string]int{}, results: map[string]int{}, calls: map[string]int{}}
}

func (r *countingRecorder) Intake(o string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.intake[o]++
}

func (r *countingRecorder) Enqueue(o string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enqueue[o]++
}

func (r *countingRecorder) Result(o string, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results[o] += n
}

func (r *countingRecorder) Call(o string, _ int, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[o]++
}

func (r *countingRecorder) snapshot() (intake, enqueue, results, calls map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := func(m map[string]int) map[string]int {
		out := make(map[string]int, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	return clone(r.intake), clone(r.enqueue), clone(r.results), clone(r.calls)
}

func TestIntake_RecordsEveryOutcome(t *testing.T) {
	t.Parallel()
	rec := newCountingRecorder()
	q := newFakeQueue()
	calls := 0
	q.enqueue = func(context.Context, topic.Request) error {
		calls++
		switch calls {
		case 1:
			return nil
		case 2:
			return topic.ErrQuotaExceeded
		default:
			return errors.New("redis down")
		}
	}
	in := newIntake(quietLogger(), adapter.NewRegistry(), q, rec, IntakeConfig{QueueSize: 4, Workers: 1})

	noText := candidate(enabledConfig())
	noText.Body = []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"x"}]}`)

	for _, c := range []Candidate{candidate(enabledConfig()), candidate(enabledConfig()), candidate(enabledConfig()), noText} {
		require.True(t, in.Submit(c))
	}
	assert.False(t, in.Submit(candidate(enabledConfig())), "the buffer is full")
	in.Start()
	require.NoError(t, in.Shutdown(context.Background()))
	assert.False(t, in.Submit(candidate(enabledConfig())))

	intake, enqueue, _, _ := rec.snapshot()
	assert.Equal(t, map[string]int{OutcomeAccepted: 4, OutcomeBufferFull: 1, OutcomeShuttingDown: 1}, intake,
		"a refusal after shutdown is not reported as saturation")
	assert.Equal(t, map[string]int{
		OutcomeQueued:        1,
		OutcomeQuotaExceeded: 1,
		OutcomeQueueError:    1,
		OutcomeNoText:        1,
	}, enqueue)
}

func TestWorker_RecordsResultsAndCalls(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{classify: func(_ context.Context, call int, texts []string) ([]topic.Classification, error) {
		if call == 1 {
			return nil, &topic.BackpressureError{RetryAfter: time.Millisecond}
		}
		return scoresFor(texts), nil
	}}
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	hit := queued("gw", billing, "cached")
	h.cache.put(cacheKeyOf(hit, "v1"), topic.Classification{})
	h.stream.push(hit, queued("gw", billing, "fresh"), queued("gw", billing, "fresh"))
	h.stream.pushDelivery(Delivery{ID: "bad", Invalid: true})
	h.start(t)

	h.waitAcked(t, 4)
	_, _, results, calls := h.recorder.snapshot()
	assert.Equal(t, map[string]int{OutcomeCacheHit: 1, OutcomeClassified: 2, OutcomeInvalid: 1}, results)
	assert.Equal(t, map[string]int{OutcomeBackpressure: 1, OutcomeOK: 1}, calls)
}
