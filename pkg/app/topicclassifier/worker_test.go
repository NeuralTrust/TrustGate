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
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStream struct {
	mu      sync.Mutex
	queue   []Delivery
	reclaim []Delivery
	acked   []string
	touched map[string]int
	trims   int
	nextID  int
}

func (s *fakeStream) push(reqs ...topic.Request) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, len(reqs))
	for i, r := range reqs {
		s.nextID++
		ids[i] = fmt.Sprintf("%d-0", s.nextID)
		s.queue = append(s.queue, Delivery{ID: ids[i], Request: r, Deliveries: 1})
	}
	return ids
}

func (s *fakeStream) pushDelivery(d Delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, d)
}

func (s *fakeStream) Read(ctx context.Context, count int, block time.Duration) ([]Delivery, error) {
	s.mu.Lock()
	if len(s.queue) > 0 {
		n := min(count, len(s.queue))
		out := slices.Clone(s.queue[:n])
		s.queue = s.queue[n:]
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()
	sleepCtx(ctx, min(block, 2*time.Millisecond))
	return nil, nil
}

func (s *fakeStream) Reclaim(context.Context, time.Duration, int) ([]Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.reclaim
	s.reclaim = nil
	return out, nil
}

func (s *fakeStream) Ack(_ context.Context, ids ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acked = append(s.acked, ids...)
	return nil
}

func (s *fakeStream) Touch(_ context.Context, ids ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.touched == nil {
		s.touched = map[string]int{}
	}
	for _, id := range ids {
		s.touched[id]++
	}
	return nil
}

func (s *fakeStream) Trim(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trims++
	return nil
}

func (s *fakeStream) touches(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.touched[id]
}

func (s *fakeStream) trimCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trims
}

func (s *fakeStream) ackedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.acked)
}

type classifyCall struct {
	gatewayTopics []topic.Topic
	threshold     *float64
	texts         []string
}

type fakeClassifier struct {
	mu         sync.Mutex
	calls      []classifyCall
	versionErr error
	classify   func(ctx context.Context, call int, texts []string) ([]topic.Classification, error)
}

func (c *fakeClassifier) Classify(ctx context.Context, topics []topic.Topic, threshold *float64, texts []string) ([]topic.Classification, error) {
	c.mu.Lock()
	c.calls = append(c.calls, classifyCall{gatewayTopics: topics, threshold: threshold, texts: slices.Clone(texts)})
	n := len(c.calls)
	fn := c.classify
	c.mu.Unlock()
	if fn != nil {
		return fn(ctx, n, texts)
	}
	return scoresFor(texts), nil
}

func (c *fakeClassifier) ModelVersion(context.Context) (string, error) {
	if c.versionErr != nil {
		return "", c.versionErr
	}
	return "v1", nil
}

func (c *fakeClassifier) recorded() []classifyCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

func scoresFor(texts []string) []topic.Classification {
	out := make([]topic.Classification, len(texts))
	for i, t := range texts {
		out[i] = topic.Classification{
			Scores:       []topic.Score{{Topic: "billing", Probability: 0.9, Matched: true}},
			Matched:      []string{"billing"},
			Windows:      1,
			ModelVersion: "v1:" + t,
		}
	}
	return out
}

type fakeCache struct {
	mu      sync.Mutex
	entries map[string]topic.Classification
	reads   int
}

func newFakeCache() *fakeCache { return &fakeCache{entries: map[string]topic.Classification{}} }

func (c *fakeCache) GetMany(_ context.Context, keys []string) (map[string]topic.Classification, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	out := map[string]topic.Classification{}
	for _, k := range keys {
		if cls, ok := c.entries[k]; ok {
			out[k] = cls
		}
	}
	return out, nil
}

func (c *fakeCache) SetMany(_ context.Context, entries map[string]topic.Classification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, cls := range entries {
		c.entries[k] = cls
	}
	return nil
}

func (c *fakeCache) put(key string, cls topic.Classification) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cls
}

func (c *fakeCache) has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}

func (c *fakeCache) readCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func (c *fakeCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

type published struct {
	req topic.Request
	cls topic.Classification
}

type fakeSink struct {
	mu  sync.Mutex
	out []published
	err error
}

func (s *fakeSink) Publish(_ context.Context, req topic.Request, cls topic.Classification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.out = append(s.out, published{req: req, cls: cls})
	return nil
}

func (s *fakeSink) all() []published {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.out)
}

type workerHarness struct {
	stream     *fakeStream
	classifier *fakeClassifier
	cache      *fakeCache
	sink       *fakeSink
	recorder   *countingRecorder
	worker     *worker
}

func testWorkerConfig() WorkerConfig {
	return WorkerConfig{
		ReadBlock:       2 * time.Millisecond,
		ClaimInterval:   5 * time.Millisecond,
		ClaimMinIdle:    time.Millisecond,
		RetryBackoff:    time.Millisecond,
		BreakerCooldown: 20 * time.Millisecond,
	}
}

func newWorkerHarness(t *testing.T, cfg WorkerConfig, classifier *fakeClassifier) *workerHarness {
	t.Helper()
	if classifier == nil {
		classifier = &fakeClassifier{}
	}
	h := &workerHarness{
		stream:     &fakeStream{},
		classifier: classifier,
		cache:      newFakeCache(),
		sink:       &fakeSink{},
		recorder:   newCountingRecorder(),
	}
	h.worker = newWorker(quietLogger(), h.stream, h.classifier, h.cache, h.sink, h.recorder, cfg)
	return h
}

func (h *workerHarness) start(t *testing.T) {
	t.Helper()
	h.worker.Start()
	t.Cleanup(func() { _ = h.worker.Shutdown(context.Background()) })
}

func (h *workerHarness) waitAcked(t *testing.T, n int) {
	t.Helper()
	require.Eventually(t, func() bool { return len(h.stream.ackedIDs()) >= n }, 2*time.Second, 2*time.Millisecond,
		"expected %d acks", n)
}

var (
	billing = []topic.Topic{{Name: "billing", Definition: "refunds and invoices"}}
	legal   = []topic.Topic{{Name: "legal", Definition: "contracts"}}
)

func queued(gateway string, topics []topic.Topic, text string) topic.Request {
	return topic.NewRequest(topic.RequestParams{
		GatewayID: gateway,
		TraceID:   "trace-" + gateway + "-" + text,
		Text:      text,
		Config:    &topic.Config{Enabled: true, Topics: topics},
	})
}

func TestWorker_ClassifiesPublishesCachesAndAcks(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	ids := h.stream.push(queued("gw", billing, "refund"), queued("gw", billing, "invoice"))
	h.start(t)

	h.waitAcked(t, 2)
	calls := h.classifier.recorded()
	require.Len(t, calls, 1, "texts sharing a catalog go in one call")
	assert.Equal(t, []string{"refund", "invoice"}, calls[0].texts)
	assert.Equal(t, billing, calls[0].gatewayTopics)

	out := h.sink.all()
	require.Len(t, out, 2)
	for _, p := range out {
		assert.Equal(t, "v1:"+p.req.Text, p.cls.ModelVersion, "each request gets its own result")
	}
	assert.Equal(t, 2, h.cache.size())
	assert.ElementsMatch(t, ids, h.stream.ackedIDs())
}

func TestWorker_CacheHitSkipsTopicGuard(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	hit := queued("gw", billing, "refund")
	cachedResult := topic.Classification{Matched: []string{"billing"}, ModelVersion: "from-cache"}
	h.cache.put(cacheKeyOf(hit, "v1"), cachedResult)

	h.stream.push(hit, queued("gw", billing, "invoice"))
	h.start(t)

	h.waitAcked(t, 2)
	calls := h.classifier.recorded()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"invoice"}, calls[0].texts)
	var fromCache bool
	for _, p := range h.sink.all() {
		if p.req.Text == "refund" {
			fromCache = p.cls.ModelVersion == "from-cache"
		}
	}
	assert.True(t, fromCache, "the cached result is the one published")
}

func TestWorker_NeverMixesGatewaysOrCatalogs(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	threshold := 0.7
	withThreshold := queued("gw-1", billing, "d")
	withThreshold.Threshold = &threshold

	h.stream.push(
		queued("gw-1", billing, "a"),
		queued("gw-2", billing, "b"),
		queued("gw-1", legal, "c"),
		withThreshold,
	)
	h.start(t)

	h.waitAcked(t, 4)
	calls := h.classifier.recorded()
	require.Len(t, calls, 4)
	for _, c := range calls {
		assert.Len(t, c.texts, 1)
	}
}

func TestWorker_DeduplicatesTextsWithinABatch(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	h.stream.push(queued("gw", billing, "same"), queued("gw", billing, "same"), queued("gw", billing, "same"))
	h.start(t)

	h.waitAcked(t, 3)
	calls := h.classifier.recorded()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"same"}, calls[0].texts)
	assert.Len(t, h.sink.all(), 3, "every request still gets its result")
}

func TestWorker_SplitsBatchesAtBatchMaxTexts(t *testing.T) {
	t.Parallel()
	cfg := testWorkerConfig()
	cfg.BatchMaxTexts = 2
	h := newWorkerHarness(t, cfg, nil)
	for i := range 5 {
		h.stream.push(queued("gw", billing, fmt.Sprint(i)))
	}
	h.start(t)

	h.waitAcked(t, 5)
	var sizes []int
	for _, c := range h.classifier.recorded() {
		sizes = append(sizes, len(c.texts))
	}
	slices.Sort(sizes)
	assert.Equal(t, []int{1, 2, 2}, sizes)
}

func TestWorker_BackpressurePausesWithoutCountingAsFailure(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{classify: func(_ context.Context, call int, texts []string) ([]topic.Classification, error) {
		if call == 1 {
			return nil, &topic.BackpressureError{RetryAfter: 30 * time.Millisecond}
		}
		return scoresFor(texts), nil
	}}
	cfg := testWorkerConfig()
	cfg.BreakerFailures = 1
	h := newWorkerHarness(t, cfg, classifier)
	h.stream.push(queued("gw", billing, "refund"))
	started := time.Now()
	h.start(t)

	h.waitAcked(t, 1)
	assert.GreaterOrEqual(t, time.Since(started), 30*time.Millisecond, "the retry waits Retry-After")
	assert.Len(t, h.sink.all(), 1)
	assert.Len(t, classifier.recorded(), 2)
	_, open := h.worker.breaker.blockedUntil(time.Now())
	assert.False(t, open, "saturation must not trip the breaker")
}

func TestWorker_DropsAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{classify: func(context.Context, int, []string) ([]topic.Classification, error) {
		return nil, errors.New("topic-guard exploded")
	}}
	cfg := testWorkerConfig()
	cfg.MaxAttempts = 2
	cfg.BreakerFailures = 100
	h := newWorkerHarness(t, cfg, classifier)
	ids := h.stream.push(queued("gw", billing, "refund"))
	h.start(t)

	h.waitAcked(t, 1)
	assert.Len(t, classifier.recorded(), 2)
	assert.Empty(t, h.sink.all())
	assert.Equal(t, ids, h.stream.ackedIDs(), "a batch that keeps failing is dropped, not left pending forever")
}

func TestWorker_BreakerOpensAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{classify: func(context.Context, int, []string) ([]topic.Classification, error) {
		return nil, errors.New("down")
	}}
	cfg := testWorkerConfig()
	cfg.MaxAttempts = 1
	cfg.BreakerFailures = 2
	cfg.BreakerCooldown = time.Hour
	h := newWorkerHarness(t, cfg, classifier)
	h.stream.push(queued("gw", billing, "a"), queued("gw", legal, "b"), queued("gw-2", legal, "c"))
	h.start(t)

	h.waitAcked(t, 2)
	_, open := h.worker.breaker.blockedUntil(time.Now())
	assert.True(t, open)
	time.Sleep(20 * time.Millisecond)
	assert.Len(t, classifier.recorded(), 2, "no call reaches topic-guard while the breaker is open")
}

func TestWorker_UnconfiguredClassifierDropsAndAcks(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{versionErr: topic.ErrClassifierNotConfigured}
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	h.stream.push(queued("gw", billing, "a"), queued("gw", legal, "b"))
	h.start(t)

	h.waitAcked(t, 2)
	assert.Empty(t, classifier.recorded())
	assert.Empty(t, h.sink.all())
}

func TestWorker_AcksInvalidDeliveries(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	h.stream.pushDelivery(Delivery{ID: "bad-1", Invalid: true, Deliveries: 1})
	h.start(t)

	h.waitAcked(t, 1)
	assert.Equal(t, []string{"bad-1"}, h.stream.ackedIDs())
	assert.Empty(t, h.classifier.recorded())
}

func TestWorker_ReclaimDropsPoisonAndClassifiesTheRest(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	h.stream.mu.Lock()
	h.stream.reclaim = []Delivery{
		{ID: "poison", Request: queued("gw", billing, "crashes us"), Deliveries: defaultMaxDeliveries + 1},
		{ID: "orphan", Request: queued("gw", billing, "left by a dead pod"), Deliveries: 2},
	}
	h.stream.mu.Unlock()
	h.start(t)

	h.waitAcked(t, 2)
	assert.ElementsMatch(t, []string{"poison", "orphan"}, h.stream.ackedIDs())
	calls := h.classifier.recorded()
	require.Len(t, calls, 1)
	assert.Equal(t, []string{"left by a dead pod"}, calls[0].texts)
}

func TestWorker_ShutdownWaitsForInFlight(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	var once sync.Once
	classifier := &fakeClassifier{classify: func(_ context.Context, _ int, texts []string) ([]topic.Classification, error) {
		once.Do(func() { close(entered) })
		time.Sleep(40 * time.Millisecond)
		return scoresFor(texts), nil
	}}
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	h.stream.push(queued("gw", billing, "slow"))
	h.worker.Start()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, h.worker.Shutdown(ctx))
	assert.Len(t, h.stream.ackedIDs(), 1, "the batch in flight finishes before Shutdown returns")
	require.NoError(t, h.worker.Shutdown(context.Background()), "a second Shutdown is a no-op")
}

func TestWorker_ShutdownDeadlineLeavesBatchPending(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	var once sync.Once
	classifier := &fakeClassifier{classify: func(ctx context.Context, _ int, _ []string) ([]topic.Classification, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	h.stream.push(queued("gw", billing, "stuck"))
	h.worker.Start()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, h.worker.Shutdown(ctx), context.DeadlineExceeded)
	assert.Empty(t, h.stream.ackedIDs(), "an interrupted batch stays pending for another consumer")
}

func TestWorker_SurvivesAPanic(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	classifier := &fakeClassifier{classify: func(_ context.Context, _ int, texts []string) ([]topic.Classification, error) {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		return scoresFor(texts), nil
	}}
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	h.stream.push(queued("gw", billing, "first"), queued("gw", legal, "second"))
	h.start(t)

	require.Eventually(t, func() bool { return len(h.sink.all()) == 1 }, 2*time.Second, 2*time.Millisecond,
		"the worker keeps classifying after a batch panics")
}

func TestWorker_ShutdownWithoutStart(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	require.NoError(t, h.worker.Shutdown(context.Background()))
	h.worker.Start()
	assert.False(t, h.worker.started, "a stopped worker cannot be started")
}

func TestWorker_ShutdownDoesNotWaitOnAnOpenBreaker(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{classify: func(context.Context, int, []string) ([]topic.Classification, error) {
		return nil, errors.New("down")
	}}
	cfg := testWorkerConfig()
	cfg.MaxAttempts = 1
	cfg.BreakerFailures = 1
	cfg.BreakerCooldown = time.Hour
	h := newWorkerHarness(t, cfg, classifier)
	h.stream.push(queued("gw", billing, "trips the breaker"))
	h.worker.Start()
	h.waitAcked(t, 1)
	h.stream.push(queued("gw", legal, "waits behind the breaker"))
	time.Sleep(10 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- h.worker.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Shutdown waited for the breaker cooldown")
	}
	assert.Len(t, h.stream.ackedIDs(), 1, "the waiting batch stays pending instead of being dropped")
}

func blockingClassifier() (c *fakeClassifier, entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	c = &fakeClassifier{classify: func(_ context.Context, _ int, texts []string) ([]topic.Classification, error) {
		once.Do(func() { close(entered) })
		<-release
		return scoresFor(texts), nil
	}}
	return c, entered, release
}

func TestWorker_TouchesEntriesItHolds(t *testing.T) {
	t.Parallel()
	classifier, entered, release := blockingClassifier()
	cfg := testWorkerConfig()
	cfg.ClaimMinIdle = 3 * time.Millisecond
	h := newWorkerHarness(t, cfg, classifier)
	ids := h.stream.push(queued("gw", billing, "slow"))
	h.start(t)
	<-entered

	require.Eventually(t, func() bool { return h.stream.touches(ids[0]) >= 2 }, 2*time.Second, time.Millisecond,
		"an entry waiting on topic-guard is kept from being reclaimed")
	close(release)
	h.waitAcked(t, 1)

	after := h.stream.touches(ids[0])
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, after, h.stream.touches(ids[0]), "an acknowledged entry is no longer touched")
}

func TestWorker_ReclaimSkipsEntriesItHolds(t *testing.T) {
	t.Parallel()
	classifier, entered, release := blockingClassifier()
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	req := queued("gw", billing, "in flight")
	ids := h.stream.push(req)
	h.start(t)
	<-entered

	h.stream.mu.Lock()
	h.stream.reclaim = []Delivery{{ID: ids[0], Request: req, Deliveries: 2}}
	h.stream.mu.Unlock()
	require.Eventually(t, func() bool {
		h.stream.mu.Lock()
		defer h.stream.mu.Unlock()
		return h.stream.reclaim == nil
	}, 2*time.Second, time.Millisecond)
	close(release)

	h.waitAcked(t, 1)
	time.Sleep(10 * time.Millisecond)
	assert.Len(t, classifier.recorded(), 1, "an entry reclaimed while held here is not dispatched again")
	assert.Len(t, h.sink.all(), 1, "and it is published once")
}

func TestWorker_ClaimLoopTrimsTheStream(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	h.start(t)
	require.Eventually(t, func() bool { return h.stream.trimCount() >= 2 }, 2*time.Second, time.Millisecond,
		"retention holds even with nothing new enqueued")
}

func TestWorker_TransientPublishFailureLeavesTheEntryPending(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	h.sink.err = errors.New("snapshot not loaded yet")
	req := queued("gw", billing, "refund")
	h.stream.push(req)
	h.start(t)

	require.Eventually(t, func() bool {
		_, _, results, _ := h.recorder.snapshot()
		return results[OutcomePublishRetry] == 1
	}, 2*time.Second, time.Millisecond)
	assert.Empty(t, h.stream.ackedIDs(), "left pending to be reclaimed and published later")
	assert.True(t, h.cache.has(cacheKeyOf(req, "v1:refund")), "the retry is served from the cache")
}

func TestWorker_UnpublishableClassificationIsAcked(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	h.sink.err = fmt.Errorf("%w: gateway gone", ErrUnpublishable)
	ids := h.stream.push(queued("gw", billing, "refund"))
	h.start(t)

	h.waitAcked(t, 1)
	assert.Equal(t, ids, h.stream.ackedIDs(), "retrying cannot help, so it is dropped")
	_, _, results, _ := h.recorder.snapshot()
	assert.Equal(t, 1, results[OutcomeUnpublishable])
}

func TestWorker_UnknownModelVersionBypassesTheCache(t *testing.T) {
	t.Parallel()
	classifier := &fakeClassifier{versionErr: errors.New("config endpoint down")}
	h := newWorkerHarness(t, testWorkerConfig(), classifier)
	req := queued("gw", billing, "refund")
	h.cache.put(cacheKeyOf(req, ""), topic.Classification{ModelVersion: "stale"})
	h.stream.push(req)
	h.start(t)

	h.waitAcked(t, 1)
	assert.Zero(t, h.cache.readCount(), "an entry of an unknown model is never served")
	require.Len(t, classifier.recorded(), 1)
	assert.True(t, h.cache.has(cacheKeyOf(req, "v1:refund")), "the result is stored under the version that scored it")
}

func TestWorker_CapsRetryAfter(t *testing.T) {
	t.Parallel()
	h := newWorkerHarness(t, testWorkerConfig(), nil)
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	h.worker.now = func() time.Time { return now }

	h.worker.pause(time.Hour)
	assert.Equal(t, now.Add(maxPause).UnixNano(), h.worker.pauseUntil.Load())
}
