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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// permissiveRecorder accepts every call, for tests that do not assert on metrics.
func permissiveRecorder(t *testing.T) *MockRecorder {
	t.Helper()
	rec := NewMockRecorder(t)
	rec.EXPECT().Intake(mock.Anything).Maybe()
	rec.EXPECT().Enqueue(mock.Anything).Maybe()
	rec.EXPECT().Result(mock.Anything, mock.Anything).Maybe()
	rec.EXPECT().Call(mock.Anything, mock.Anything, mock.Anything).Maybe()
	return rec
}

type silentT struct{}

func (silentT) Logf(string, ...any)   {}
func (silentT) Errorf(string, ...any) {}
func (silentT) FailNow()              {}

// recorded reports whether rec saw the call, without failing the test, so it can be polled.
func recorded(rec *MockRecorder, method string, args ...any) bool {
	return rec.AssertCalled(silentT{}, method, args...)
}

func TestIntake_RecordsEveryOutcome(t *testing.T) {
	t.Parallel()
	rec := NewMockRecorder(t)
	rec.EXPECT().Intake(OutcomeAccepted).Times(4)
	rec.EXPECT().Intake(OutcomeBufferFull).Once()
	rec.EXPECT().Intake(OutcomeShuttingDown).Once()
	rec.EXPECT().Enqueue(OutcomeQueued).Once()
	rec.EXPECT().Enqueue(OutcomeQuotaExceeded).Once()
	rec.EXPECT().Enqueue(OutcomeQueueError).Once()
	rec.EXPECT().Enqueue(OutcomeNoText).Once()

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
	require.False(t, in.Submit(candidate(enabledConfig())), "the buffer is full")
	in.Start()
	require.NoError(t, in.Shutdown(context.Background()))
	require.False(t, in.Submit(candidate(enabledConfig())), "a refusal after shutdown is not reported as saturation")
}

func TestWorker_RecordsResultsAndCalls(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{classify: func(_ context.Context, call int, texts []string) ([]topic.Classification, error) {
		if call == 1 {
			return nil, &topic.BackpressureError{RetryAfter: time.Millisecond}
		}
		return scoresFor(texts), nil
	}}
	rec := NewMockRecorder(t)
	rec.EXPECT().Result(OutcomeCacheHit, 1).Once()
	rec.EXPECT().Result(OutcomeClassified, 2).Once()
	rec.EXPECT().Result(OutcomeInvalid, 1).Once()
	rec.EXPECT().Call(OutcomeBackpressure, 1, mock.Anything).Once()
	rec.EXPECT().Call(OutcomeOK, 1, mock.Anything).Once()

	h := newWorkerHarnessWith(t, testWorkerConfig(), classifier, rec)
	hit := queued("gw", billing, "cached")
	h.cache.put(cacheKeyOf(hit, "v1"), topic.Classification{})
	h.stream.push(hit, queued("gw", billing, "fresh"), queued("gw", billing, "fresh"))
	h.stream.pushDelivery(Delivery{ID: "bad", Invalid: true})
	h.start(t)

	h.waitAcked(t, 4)
	require.NoError(t, h.worker.Shutdown(context.Background()))
}
