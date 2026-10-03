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
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	defaultIntakeQueueSize      = 1000
	defaultIntakeWorkers        = 2
	defaultIntakeEnqueueTimeout = 500 * time.Millisecond
	defaultIntakeMaxBufferBytes = 64 << 20

	conversationIOTimeout = 500 * time.Millisecond
)

// Candidate is one request offered for labeling. SessionID is the effective
// session id (empty for a hidden generated one). BufferOnly marks a request
// sampling left out that is still read to keep its conversation buffer
// complete: it is never classified.
type Candidate struct {
	GatewayID    string
	ConsumerID   string
	TraceID      string
	SessionID    string
	SourceFormat adapter.Format
	Body         []byte
	Config       *trafficlabel.Config
	LabelSets    []trafficlabel.LabelSet
	ReceivedAt   time.Time
	BufferOnly   bool
}

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

//go:generate mockery --name=Intake --dir=. --output=./mocks --filename=intake_mock.go --case=underscore --with-expecter
type Intake interface {
	Submit(c Candidate) bool
	Start()
	Shutdown(ctx context.Context) error
}

var _ Intake = (*intake)(nil)

// IntakeOption configures optional intake collaborators.
type IntakeOption func(*intake)

// WithConversationBuffer lets the intake extend the labeling window of OpenAI
// Responses continuations with the earlier turns of their conversation.
func WithConversationBuffer(buffer ConversationBuffer) IntakeOption {
	return func(i *intake) { i.conversations = buffer }
}

type intake struct {
	logger        *slog.Logger
	decoder       RequestDecoder
	queue         Queue
	recorder      Recorder
	cfg           IntakeConfig
	conversations ConversationBuffer

	ch       chan Candidate
	wg       sync.WaitGroup
	buffered atomic.Int64

	mu      sync.RWMutex
	started bool
	closed  bool
	cancel  context.CancelFunc
}

func NewIntake(
	logger *slog.Logger,
	decoder RequestDecoder,
	queue Queue,
	recorder Recorder,
	cfg IntakeConfig,
	opts ...IntakeOption,
) Intake {
	return newIntake(logger, decoder, queue, recorder, cfg, opts...)
}

func newIntake(
	logger *slog.Logger,
	decoder RequestDecoder,
	queue Queue,
	recorder Recorder,
	cfg IntakeConfig,
	opts ...IntakeOption,
) *intake {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()
	in := &intake{
		logger:   logger,
		decoder:  decoder,
		queue:    queue,
		recorder: recorder,
		cfg:      cfg,
		ch:       make(chan Candidate, cfg.QueueSize),
	}
	for _, opt := range opts {
		opt(in)
	}
	return in
}

func (i *intake) Submit(c Candidate) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if c.BufferOnly && !i.buffers(c) {
		return false
	}
	if i.closed {
		i.recordIntake(c, OutcomeShuttingDown)
		return false
	}
	size := int64(len(c.Body))
	if i.buffered.Add(size) > i.cfg.MaxBufferBytes {
		i.buffered.Add(-size)
		i.recordIntake(c, OutcomeBufferFull)
		return false
	}
	select {
	case i.ch <- c:
		i.recordIntake(c, OutcomeAccepted)
		return true
	default:
		i.buffered.Add(-size)
		i.recordIntake(c, OutcomeBufferFull)
		return false
	}
}

// recordIntake skips buffer-only candidates: the middleware already counted
// them as sampled out.
func (i *intake) recordIntake(c Candidate, outcome string) {
	if c.BufferOnly {
		return
	}
	i.recorder.Intake(outcome)
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
			i.logger.Error("traffic labels intake panicked",
				slog.String("gateway_id", c.GatewayID),
				slog.Any("panic", r),
				slog.String("stack", string(debug.Stack())))
		}
	}()
	req, ok := i.build(ctx, c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, i.cfg.EnqueueTimeout)
	defer cancel()
	err := i.queue.Enqueue(ctx, req)
	switch {
	case err == nil:
		i.recorder.Enqueue(OutcomeQueued)
	case errors.Is(err, trafficlabel.ErrQuotaExceeded):
		i.recorder.Enqueue(OutcomeQuotaExceeded)
		i.logger.Debug("traffic labels dropped: gateway quota exceeded",
			slog.String("gateway_id", c.GatewayID))
	default:
		i.recorder.Enqueue(OutcomeQueueError)
		i.logger.Warn("traffic labels enqueue failed",
			slog.String("gateway_id", c.GatewayID),
			slog.String("error", err.Error()))
	}
}

func (i *intake) build(ctx context.Context, c Candidate) (trafficlabel.Request, bool) {
	if !c.Config.IsEnabled() || len(c.LabelSets) == 0 {
		return trafficlabel.Request{}, false
	}
	text := i.text(ctx, c)
	if c.BufferOnly {
		return trafficlabel.Request{}, false
	}
	if text == "" {
		i.recorder.Enqueue(OutcomeNoText)
		return trafficlabel.Request{}, false
	}
	return trafficlabel.NewRequest(trafficlabel.RequestParams{
		GatewayID:  c.GatewayID,
		ConsumerID: c.ConsumerID,
		TraceID:    c.TraceID,
		Text:       text,
		Config:     c.Config,
		LabelSets:  c.LabelSets,
		ReceivedAt: c.ReceivedAt,
	}), true
}

// text is the user text to classify. Only OpenAI Responses requests with a
// session use the conversation buffer, and never together with the body
// history: a continuation (previous_response_id or conversation) only carries
// its new turn, so the window is the buffer plus that turn; any other request
// carries its own history, so the body alone is the window. Either way the
// buffer is left holding the conversation's most recent user messages.
func (i *intake) text(ctx context.Context, c Candidate) string {
	msgs := userMessages(i.decoder, c.Body, c.SourceFormat)
	if !i.buffers(c) {
		return windowText(msgs, c.Config.Window())
	}
	key := ConversationKey{GatewayID: c.GatewayID, ConsumerID: c.ConsumerID, SessionID: c.SessionID}
	if isResponsesContinuation(c.Body) {
		msgs = append(i.loadConversation(ctx, key), msgs...)
	}
	msgs = capConversation(msgs)
	if len(msgs) > 0 {
		i.saveConversation(ctx, key, msgs)
	}
	return windowText(msgs, c.Config.Window())
}

func (i *intake) buffers(c Candidate) bool {
	return i.conversations != nil && c.SessionID != "" && c.SourceFormat == adapter.FormatOpenAIResponses
}

func (i *intake) loadConversation(ctx context.Context, key ConversationKey) []string {
	ctx, cancel := context.WithTimeout(ctx, conversationIOTimeout)
	defer cancel()
	msgs, err := i.conversations.Load(ctx, key)
	if err != nil {
		i.logger.Debug("traffic labels: conversation buffer not read, labeling the new turn only",
			slog.String("gateway_id", key.GatewayID), slog.String("error", err.Error()))
		return nil
	}
	return msgs
}

func (i *intake) saveConversation(ctx context.Context, key ConversationKey, msgs []string) {
	ctx, cancel := context.WithTimeout(ctx, conversationIOTimeout)
	defer cancel()
	if err := i.conversations.Save(ctx, key, msgs); err != nil {
		i.logger.Debug("traffic labels: conversation buffer not written",
			slog.String("gateway_id", key.GatewayID), slog.String("error", err.Error()))
	}
}

func isResponsesContinuation(body []byte) bool {
	var probe struct {
		PreviousResponseID json.RawMessage `json:"previous_response_id"`
		Conversation       json.RawMessage `json:"conversation"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	return present(probe.PreviousResponseID) || present(probe.Conversation)
}

func present(raw json.RawMessage) bool {
	switch string(raw) {
	case "", "null", `""`:
		return false
	}
	return true
}
