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
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	defaultIntakeQueueSize      = 1000
	defaultIntakeWorkers        = 2
	defaultIntakeEnqueueTimeout = 500 * time.Millisecond
	defaultIntakeMaxBufferBytes = 64 << 20
)

// Candidate is what the request path hands to the intake: an owned copy of
// the request body plus what is needed to turn it into a classification
// request later, off the request path.
type Candidate struct {
	GatewayID    string
	ConsumerID   string
	TraceID      string
	SourceFormat adapter.Format
	Body         []byte
	Config       *topic.Config
	ReceivedAt   time.Time
}

// IntakeConfig sizes the intake. Zero values fall back to defaults.
// MaxBufferBytes bounds the request bodies held while they wait to be queued,
// whatever their number: large bodies fill it long before QueueSize does.
type IntakeConfig struct {
	QueueSize      int
	Workers        int
	EnqueueTimeout time.Duration
	MaxBufferBytes int64
}

func (c IntakeConfig) withDefaults() IntakeConfig {
	if c.QueueSize <= 0 {
		c.QueueSize = defaultIntakeQueueSize
	}
	if c.Workers <= 0 {
		c.Workers = defaultIntakeWorkers
	}
	if c.EnqueueTimeout <= 0 {
		c.EnqueueTimeout = defaultIntakeEnqueueTimeout
	}
	if c.MaxBufferBytes <= 0 {
		c.MaxBufferBytes = defaultIntakeMaxBufferBytes
	}
	return c
}

// Intake accepts classification candidates from the request path without
// ever blocking it, and turns them into queued requests on its own goroutines.
//
//go:generate mockery --name=Intake --dir=. --output=./mocks --filename=intake_mock.go --case=underscore --with-expecter
type Intake interface {
	// Submit offers a candidate and reports whether it was accepted. It never
	// blocks: when the buffer is full or the intake is shut down it drops.
	Submit(c Candidate) bool
	Start()
	// Shutdown stops accepting candidates and waits for the buffered ones to
	// be queued. If ctx expires first, in-flight enqueues are cancelled and
	// whatever is still buffered is dropped.
	Shutdown(ctx context.Context) error
}

var _ Intake = (*intake)(nil)

type intake struct {
	logger   *slog.Logger
	decoder  RequestDecoder
	queue    Queue
	recorder Recorder
	cfg      IntakeConfig

	ch       chan Candidate
	wg       sync.WaitGroup
	buffered atomic.Int64

	mu      sync.RWMutex
	started bool
	closed  bool
	cancel  context.CancelFunc
}

// NewIntake builds an intake that decodes candidates with decoder and hands
// the resulting requests to queue. A nil recorder records nothing.
func NewIntake(logger *slog.Logger, decoder RequestDecoder, queue Queue, recorder Recorder, cfg IntakeConfig) Intake {
	return newIntake(logger, decoder, queue, recorder, cfg)
}

func newIntake(logger *slog.Logger, decoder RequestDecoder, queue Queue, recorder Recorder, cfg IntakeConfig) *intake {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()
	return &intake{
		logger:   logger,
		decoder:  decoder,
		queue:    queue,
		recorder: orNop(recorder),
		cfg:      cfg,
		ch:       make(chan Candidate, cfg.QueueSize),
	}
}

func (i *intake) Submit(c Candidate) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.closed {
		i.recorder.Intake(OutcomeShuttingDown)
		return false
	}
	size := int64(len(c.Body))
	if i.buffered.Add(size) > i.cfg.MaxBufferBytes {
		i.buffered.Add(-size)
		i.recorder.Intake(OutcomeBufferFull)
		return false
	}
	select {
	case i.ch <- c:
		i.recorder.Intake(OutcomeAccepted)
		return true
	default:
		i.buffered.Add(-size)
		i.recorder.Intake(OutcomeBufferFull)
		return false
	}
}

func (i *intake) Start() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.started || i.closed {
		return
	}
	i.started = true
	ctx, cancel := context.WithCancel(context.Background())
	i.cancel = cancel
	for range i.cfg.Workers {
		i.wg.Add(1)
		go i.run(ctx)
	}
}

func (i *intake) Shutdown(ctx context.Context) error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	close(i.ch)
	cancel := i.cancel
	i.mu.Unlock()

	if cancel == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		i.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		cancel()
		return nil
	case <-ctx.Done():
		cancel()
		<-done
		return ctx.Err()
	}
}

func (i *intake) run(ctx context.Context) {
	defer i.wg.Done()
	for c := range i.ch {
		if ctx.Err() == nil {
			i.process(ctx, c)
		}
		i.buffered.Add(-int64(len(c.Body)))
	}
}

func (i *intake) process(ctx context.Context, c Candidate) {
	defer func() {
		if r := recover(); r != nil {
			i.logger.Error("topic classification intake panicked",
				slog.String("gateway_id", c.GatewayID),
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())))
		}
	}()
	req, ok := i.build(c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, i.cfg.EnqueueTimeout)
	defer cancel()
	err := i.queue.Enqueue(ctx, req)
	switch {
	case err == nil:
		i.recorder.Enqueue(OutcomeQueued)
	case errors.Is(err, topic.ErrQuotaExceeded):
		i.recorder.Enqueue(OutcomeQuotaExceeded)
		i.logger.Debug("topic classification dropped: gateway quota exceeded",
			slog.String("gateway_id", c.GatewayID))
	default:
		i.recorder.Enqueue(OutcomeQueueError)
		i.logger.Warn("topic classification enqueue failed",
			slog.String("gateway_id", c.GatewayID),
			slog.String("error", err.Error()))
	}
}

func (i *intake) build(c Candidate) (topic.Request, bool) {
	if !c.Config.IsEnabled() {
		return topic.Request{}, false
	}
	text := userText(i.decoder, c.Body, c.SourceFormat, c.Config.Window())
	if text == "" {
		i.recorder.Enqueue(OutcomeNoText)
		return topic.Request{}, false
	}
	return topic.NewRequest(topic.RequestParams{
		GatewayID:  c.GatewayID,
		ConsumerID: c.ConsumerID,
		TraceID:    c.TraceID,
		Text:       text,
		Config:     c.Config,
		ReceivedAt: c.ReceivedAt,
	}), true
}
