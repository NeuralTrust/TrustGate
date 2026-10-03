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

package trafficlabels

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

const (
	defaultWorkerConcurrency = 8
	defaultReadCount         = 64
	defaultReadBlock         = time.Second
	defaultBatchMaxTexts     = 8
	defaultClaimInterval     = 30 * time.Second
	defaultClaimMinIdle      = time.Minute
	defaultMaxAttempts       = 3
	defaultMaxDeliveries     = 3
	defaultRetryBackoff      = 500 * time.Millisecond
	defaultBreakerFailures   = 5
	defaultBreakerCooldown   = 30 * time.Second

	maxBatchTexts    = 128
	maxRetryBackoff  = 10 * time.Second
	maxPause         = 30 * time.Second
	readErrorBackoff = time.Second
	ackTimeout       = 5 * time.Second
)

var errShuttingDown = errors.New("traffic labels: shutting down")

type WorkerConfig struct {
	Concurrency     int
	ReadCount       int
	ReadBlock       time.Duration
	BatchMaxTexts   int
	ClaimInterval   time.Duration
	ClaimMinIdle    time.Duration
	MaxAttempts     int
	MaxDeliveries   int64
	RetryBackoff    time.Duration
	BreakerFailures int
	BreakerCooldown time.Duration
}

func (c WorkerConfig) withDefaults() WorkerConfig {
	c.Concurrency = positiveOr(c.Concurrency, defaultWorkerConcurrency)
	c.ReadCount = positiveOr(c.ReadCount, defaultReadCount)
	c.ReadBlock = positiveOr(c.ReadBlock, defaultReadBlock)
	c.BatchMaxTexts = min(positiveOr(c.BatchMaxTexts, defaultBatchMaxTexts), maxBatchTexts)
	c.ClaimInterval = positiveOr(c.ClaimInterval, defaultClaimInterval)
	c.ClaimMinIdle = positiveOr(c.ClaimMinIdle, defaultClaimMinIdle)
	c.MaxAttempts = positiveOr(c.MaxAttempts, defaultMaxAttempts)
	c.MaxDeliveries = positiveOr(c.MaxDeliveries, defaultMaxDeliveries)
	c.RetryBackoff = positiveOr(c.RetryBackoff, defaultRetryBackoff)
	c.BreakerFailures = positiveOr(c.BreakerFailures, defaultBreakerFailures)
	c.BreakerCooldown = positiveOr(c.BreakerCooldown, defaultBreakerCooldown)
	return c
}

func positiveOr[T int | int64 | time.Duration](v, fallback T) T {
	if v <= 0 {
		return fallback
	}
	return v
}

//go:generate mockery --name=Worker --dir=. --output=./mocks --filename=worker_mock.go --case=underscore --with-expecter
type Worker interface {
	Start()
	Shutdown(ctx context.Context) error
}

var _ Worker = (*worker)(nil)

type worker struct {
	logger     *slog.Logger
	stream     Stream
	classifier Classifier
	cache      Cache
	sink       Sink
	recorder   Recorder
	cfg        WorkerConfig
	breaker    *breaker
	now        func() time.Time

	pauseUntil atomic.Int64
	sem        chan struct{}
	stopping   chan struct{}

	loops    sync.WaitGroup
	inflight sync.WaitGroup

	mu       sync.Mutex
	started  bool
	stopped  bool
	stopRead context.CancelFunc
	stopWork context.CancelFunc

	heldMu sync.Mutex
	held   map[string]struct{}
}

func NewWorker(logger *slog.Logger, stream Stream, classifier Classifier, cache Cache, sink Sink, recorder Recorder, cfg WorkerConfig) Worker {
	return newWorker(logger, stream, classifier, cache, sink, recorder, cfg)
}

func newWorker(logger *slog.Logger, stream Stream, classifier Classifier, cache Cache, sink Sink, recorder Recorder, cfg WorkerConfig) *worker {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()
	return &worker{
		logger:     logger,
		stream:     stream,
		classifier: classifier,
		cache:      cache,
		sink:       sink,
		recorder:   recorder,
		cfg:        cfg,
		breaker:    newBreaker(cfg.BreakerFailures, cfg.BreakerCooldown),
		now:        time.Now,
		sem:        make(chan struct{}, cfg.Concurrency),
		stopping:   make(chan struct{}),
		held:       make(map[string]struct{}),
	}
}

func (w *worker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.stopped {
		return
	}
	w.started = true
	readCtx, stopRead := context.WithCancel(context.Background())
	workCtx, stopWork := context.WithCancel(context.Background())
	w.stopRead, w.stopWork = stopRead, stopWork
	w.loops.Add(3)
	go w.readLoop(readCtx, workCtx)
	go w.claimLoop(readCtx, workCtx)
	go w.heartbeatLoop(readCtx)
}

func (w *worker) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	if w.stopped || !w.started {
		w.stopped = true
		w.mu.Unlock()
		return nil
	}
	w.stopped = true
	stopRead, stopWork := w.stopRead, w.stopWork
	w.mu.Unlock()

	close(w.stopping)
	stopRead()
	done := make(chan struct{})
	go func() {
		w.loops.Wait()
		w.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		stopWork()
		return nil
	case <-ctx.Done():
		stopWork()
		<-done
		return ctx.Err()
	}
}

func (w *worker) readLoop(readCtx, workCtx context.Context) {
	defer w.loops.Done()
	for {
		if !w.ready(readCtx) {
			return
		}
		deliveries, err := w.stream.Read(readCtx, w.cfg.ReadCount, w.cfg.ReadBlock)
		if readCtx.Err() != nil {
			return
		}
		if err != nil {
			w.logger.Warn("traffic labels read failed", slog.String("error", err.Error()))
			if !sleepCtx(readCtx, readErrorBackoff) {
				return
			}
			continue
		}
		w.dispatch(readCtx, workCtx, deliveries)
	}
}

func (w *worker) claimLoop(readCtx, workCtx context.Context) {
	defer w.loops.Done()
	ticker := time.NewTicker(w.cfg.ClaimInterval)
	defer ticker.Stop()
	for {
		select {
		case <-readCtx.Done():
			return
		case <-ticker.C:
		}
		if err := w.stream.Trim(readCtx); err != nil && readCtx.Err() == nil {
			w.logger.Debug("traffic labels trim failed", slog.String("error", err.Error()))
		}
		if !w.ready(readCtx) {
			return
		}
		deliveries, err := w.stream.Reclaim(readCtx, w.cfg.ClaimMinIdle, w.cfg.ReadCount)
		if err != nil {
			if readCtx.Err() == nil {
				w.logger.Warn("traffic labels reclaim failed", slog.String("error", err.Error()))
			}
			continue
		}
		keep := deliveries[:0]
		var poison []string
		for _, d := range deliveries {
			switch {
			case w.holds(d.ID):
			case d.Deliveries > w.cfg.MaxDeliveries:
				poison = append(poison, d.ID)
			default:
				keep = append(keep, d)
			}
		}
		if len(poison) > 0 {
			w.recorder.Result(OutcomePoison, len(poison))
			w.logger.Warn("traffic labels dropped entries handed out too many times",
				slog.Int("count", len(poison)), slog.Int64("max_deliveries", w.cfg.MaxDeliveries))
			w.ack(workCtx, poison)
		}
		w.dispatch(readCtx, workCtx, keep)
	}
}

func (w *worker) heartbeatLoop(readCtx context.Context) {
	defer w.loops.Done()
	ticker := time.NewTicker(max(w.cfg.ClaimMinIdle/3, time.Millisecond))
	defer ticker.Stop()
	for {
		select {
		case <-readCtx.Done():
			return
		case <-ticker.C:
		}
		ids := w.heldIDs()
		if len(ids) == 0 {
			continue
		}
		if err := w.stream.Touch(readCtx, ids...); err != nil && readCtx.Err() == nil {
			w.logger.Warn("traffic labels heartbeat failed",
				slog.Int("count", len(ids)), slog.String("error", err.Error()))
		}
	}
}

func (w *worker) hold(ds []Delivery) {
	w.heldMu.Lock()
	defer w.heldMu.Unlock()
	for _, d := range ds {
		w.held[d.ID] = struct{}{}
	}
}

func (w *worker) release(ds []Delivery) {
	w.heldMu.Lock()
	defer w.heldMu.Unlock()
	for _, d := range ds {
		delete(w.held, d.ID)
	}
}

func (w *worker) holds(id string) bool {
	w.heldMu.Lock()
	defer w.heldMu.Unlock()
	_, ok := w.held[id]
	return ok
}

func (w *worker) heldIDs() []string {
	w.heldMu.Lock()
	defer w.heldMu.Unlock()
	ids := make([]string, 0, len(w.held))
	for id := range w.held {
		ids = append(ids, id)
	}
	return ids
}

type batchKey struct {
	gatewayID   string
	catalogHash string
	registryID  string
	model       string
}

func keyOf(req trafficlabel.Request) batchKey {
	return batchKey{gatewayID: req.GatewayID, catalogHash: req.CatalogHash, registryID: req.RegistryID, model: req.Model}
}

func (w *worker) dispatch(readCtx, workCtx context.Context, deliveries []Delivery) {
	var invalid []string
	var valid []Delivery
	var order []batchKey
	groups := make(map[batchKey][]Delivery)
	for _, d := range deliveries {
		if d.Invalid {
			invalid = append(invalid, d.ID)
			continue
		}
		valid = append(valid, d)
		k := keyOf(d.Request)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], d)
	}
	if len(invalid) > 0 {
		w.recorder.Result(OutcomeInvalid, len(invalid))
		w.ack(workCtx, invalid)
	}
	w.hold(valid)
	var batches [][]Delivery
	for _, k := range order {
		group := groups[k]
		for start := 0; start < len(group); start += w.cfg.BatchMaxTexts {
			batches = append(batches, group[start:min(start+w.cfg.BatchMaxTexts, len(group))])
		}
	}
	for i, batch := range batches {
		select {
		case w.sem <- struct{}{}:
		case <-readCtx.Done():
			for _, rest := range batches[i:] {
				w.release(rest)
			}
			return
		}
		w.inflight.Add(1)
		go w.handle(workCtx, batch)
	}
}

type pendingText struct {
	key        string
	text       string
	deliveries []Delivery
}

func (w *worker) handle(ctx context.Context, batch []Delivery) {
	defer w.inflight.Done()
	defer func() { <-w.sem }()
	defer w.release(batch)
	defer func() {
		if r := recover(); r != nil {
			w.logger.Error("traffic labels batch panicked",
				slog.String("gateway_id", batch[0].Request.GatewayID),
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())))
		}
	}()

	first := batch[0].Request
	var texts []*pendingText
	byKey := make(map[string]*pendingText)
	for _, d := range batch {
		key := cacheKeyOf(d.Request)
		if p, ok := byKey[key]; ok {
			p.deliveries = append(p.deliveries, d)
			continue
		}
		p := &pendingText{key: key, text: d.Request.Text, deliveries: []Delivery{d}}
		byKey[key] = p
		texts = append(texts, p)
	}

	hits := w.cached(ctx, texts)
	var done []string
	var misses []*pendingText
	for _, p := range texts {
		cls, ok := hits[p.key]
		if !ok {
			misses = append(misses, p)
			continue
		}
		w.recorder.Result(OutcomeCacheHit, len(p.deliveries))
		done = append(done, w.publishAll(ctx, p.deliveries, cls)...)
	}

	classified := make(map[string]trafficlabel.Classification, len(misses))
	var unavailable error
	for _, p := range misses {
		var cls trafficlabel.Classification
		err := unavailable
		if err == nil {
			cls, err = w.classify(ctx, ClassifyInput{
				GatewayID:  first.GatewayID,
				RegistryID: first.RegistryID,
				Model:      first.Model,
				Labels:     first.Labels,
				Text:       p.text,
			})
		}
		if err == nil {
			classified[p.key] = cls
			w.recorder.Result(OutcomeClassified, len(p.deliveries))
			done = append(done, w.publishAll(ctx, p.deliveries, cls)...)
			continue
		}
		if ctx.Err() != nil || errors.Is(err, errShuttingDown) {
			break
		}
		outcome := OutcomeFailed
		if errors.Is(err, trafficlabel.ErrClassifierUnavailable) {
			outcome = OutcomeUnconfigured
			unavailable = err
		}
		w.logger.Warn("traffic labels dropped a request after retrying",
			slog.String("gateway_id", first.GatewayID),
			slog.String("registry_id", first.RegistryID),
			slog.String("outcome", outcome),
			slog.String("error", err.Error()))
		w.recorder.Result(outcome, len(p.deliveries))
		done = append(done, deliveryIDs(p.deliveries)...)
	}
	w.store(ctx, classified)
	w.ack(ctx, done)
}

func cacheKeyOf(req trafficlabel.Request) string {
	return trafficlabel.CacheKey(req.GatewayID, req.TextHash, req.CatalogHash, req.RegistryID, req.Model)
}

func (w *worker) classify(ctx context.Context, in ClassifyInput) (trafficlabel.Classification, error) {
	attempts := 0
	for {
		if !w.ready(ctx) {
			return trafficlabel.Classification{}, w.interrupted(ctx)
		}
		started := w.now()
		cls, err := w.classifier.Classify(ctx, in)
		elapsed := w.now().Sub(started)
		if err == nil {
			w.recorder.Call(OutcomeOK, elapsed)
			w.breaker.success()
			return cls, nil
		}
		var bp *trafficlabel.BackpressureError
		switch {
		case errors.As(err, &bp):
			w.recorder.Call(OutcomeBackpressure, elapsed)
			w.pause(bp.RetryAfter)
			continue
		case ctx.Err() != nil:
			return trafficlabel.Classification{}, ctx.Err()
		case errors.Is(err, trafficlabel.ErrClassifierUnavailable), errors.Is(err, trafficlabel.ErrInvalidAnswer):
			w.recorder.Call(OutcomeError, elapsed)
			return trafficlabel.Classification{}, err
		}
		w.recorder.Call(OutcomeError, elapsed)
		w.breaker.failure(w.now())
		attempts++
		if attempts >= w.cfg.MaxAttempts {
			return trafficlabel.Classification{}, err
		}
		if !w.wait(ctx, w.backoff(attempts)) {
			return trafficlabel.Classification{}, w.interrupted(ctx)
		}
	}
}

func (w *worker) interrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errShuttingDown
}

func (w *worker) backoff(attempt int) time.Duration {
	d := w.cfg.RetryBackoff << (attempt - 1)
	if d <= 0 || d > maxRetryBackoff {
		d = maxRetryBackoff
	}
	jitter := time.Duration(rand.Int63n(int64(w.cfg.RetryBackoff)/2 + 1)) // #nosec G404 -- retry jitter, not a secret
	return d + jitter
}

func (w *worker) pause(d time.Duration) {
	until := w.now().Add(min(d, maxPause)).UnixNano()
	for {
		current := w.pauseUntil.Load()
		if current >= until || w.pauseUntil.CompareAndSwap(current, until) {
			return
		}
	}
}

func (w *worker) ready(ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		now := w.now()
		var wait time.Duration
		if until := time.Unix(0, w.pauseUntil.Load()); now.Before(until) {
			wait = until.Sub(now)
		} else if until, open := w.breaker.blockedUntil(now); open {
			wait = until.Sub(now)
		}
		if wait <= 0 {
			return true
		}
		if !w.wait(ctx, wait) {
			return false
		}
	}
}

func (w *worker) wait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-w.stopping:
		return false
	}
}

func (w *worker) cached(ctx context.Context, texts []*pendingText) map[string]trafficlabel.Classification {
	if w.cache == nil {
		return nil
	}
	keys := make([]string, len(texts))
	for i, p := range texts {
		keys[i] = p.key
	}
	hits, err := w.cache.GetMany(ctx, keys)
	if err != nil {
		w.logger.Debug("traffic labels cache read failed", slog.String("error", err.Error()))
		return nil
	}
	return hits
}

func (w *worker) store(ctx context.Context, classified map[string]trafficlabel.Classification) {
	if w.cache == nil || len(classified) == 0 {
		return
	}
	entries := make(map[string]trafficlabel.Classification, len(classified))
	for key, cls := range classified {
		entries[key] = cls.Cached()
	}
	if err := w.cache.SetMany(ctx, entries); err != nil {
		w.logger.Debug("traffic labels cache write failed", slog.String("error", err.Error()))
	}
}

func (w *worker) publishAll(ctx context.Context, ds []Delivery, cls trafficlabel.Classification) []string {
	done := make([]string, 0, len(ds))
	for _, d := range ds {
		err := w.sink.Publish(ctx, d.Request, cls)
		if err == nil {
			done = append(done, d.ID)
			continue
		}
		w.logger.Warn("traffic labels publish failed",
			slog.String("gateway_id", d.Request.GatewayID),
			slog.String("trace_id", d.Request.TraceID),
			slog.String("error", err.Error()))
		if errors.Is(err, ErrUnpublishable) {
			w.recorder.Result(OutcomeUnpublishable, 1)
			done = append(done, d.ID)
			continue
		}
		w.recorder.Result(OutcomePublishRetry, 1)
	}
	return done
}

// Detached from cancellation so a batch finished during shutdown is still acked, not classified twice.
func (w *worker) ack(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()
	if err := w.stream.Ack(ctx, ids...); err != nil {
		w.logger.Warn("traffic labels ack failed",
			slog.Int("count", len(ids)), slog.String("error", err.Error()))
	}
}

func deliveryIDs(ds []Delivery) []string {
	ids := make([]string, len(ds))
	for i, d := range ds {
		ids[i] = d.ID
	}
	return ids
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
