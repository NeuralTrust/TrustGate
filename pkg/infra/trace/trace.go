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

package trace

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/google/uuid"
)

type Metadata struct {
	GatewayID    string
	TeamID       string
	ConsumerID   string
	ConsumerName string
	Path         string
	Method       string
	IP           string
	SessionID    string
	Kind         string
}

type RequestTrace struct {
	traceID   string
	meta      Metadata
	startedAt time.Time

	requestTracesEnabled atomic.Bool
	pluginTracesEnabled  atomic.Bool

	pending  int64
	emitOnce sync.Once

	mu           sync.Mutex
	endedAt      time.Time
	spans        []*Span
	emitFn       func()
	statusReason string
}

func New(traceID string, meta Metadata) *RequestTrace {
	if traceID == "" {
		traceID = uuid.New().String()
	}
	t := &RequestTrace{
		traceID:   traceID,
		meta:      meta,
		startedAt: time.Now(),
		pending:   1,
	}
	t.requestTracesEnabled.Store(true)
	t.pluginTracesEnabled.Store(true)
	return t
}

// OnComplete registers the callback fired once the request and all of its
// asynchronous spans (e.g. post_response plugins) have finished. It must be set
// before the request hold is released via Done.
func (t *RequestTrace) OnComplete(fn func()) {
	t.mu.Lock()
	t.emitFn = fn
	t.mu.Unlock()
}

// AddAsync registers asynchronous work (a detached span) that must complete
// before the trace is published. Pair every AddAsync with a Done.
func (t *RequestTrace) AddAsync() {
	atomic.AddInt64(&t.pending, 1)
}

// Done releases one unit of outstanding work (the request hold or an async
// span). The last Done fires OnComplete exactly once.
func (t *RequestTrace) Done() {
	if atomic.AddInt64(&t.pending, -1) != 0 {
		return
	}
	t.mu.Lock()
	fn := t.emitFn
	t.mu.Unlock()
	t.emitOnce.Do(func() {
		t.End()
		if fn != nil {
			fn()
		}
	})
}

func (t *RequestTrace) TraceID() string { return t.traceID }

func (t *RequestTrace) Metadata() Metadata {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.meta
}

func (t *RequestTrace) SetConsumer(id, name string) {
	t.mu.Lock()
	t.meta.ConsumerID = id
	t.meta.ConsumerName = name
	t.mu.Unlock()
}

func (t *RequestTrace) StartedAt() time.Time { return t.startedAt }

func (t *RequestTrace) SetStatusReason(reason string) {
	if reason == "" {
		return
	}
	t.mu.Lock()
	t.statusReason = reason
	t.mu.Unlock()
}

func (t *RequestTrace) StatusReason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.statusReason
}

func (t *RequestTrace) SetGating(requestTraces, pluginTraces bool) {
	t.requestTracesEnabled.Store(requestTraces)
	t.pluginTracesEnabled.Store(pluginTraces)
}

func (t *RequestTrace) RequestTracesEnabled() bool { return t.requestTracesEnabled.Load() }

func (t *RequestTrace) PluginTracesEnabled() bool { return t.pluginTracesEnabled.Load() }

func (t *RequestTrace) StartSpan(spanType SpanType, name string) *Span {
	s := newSpan(spanType, name)
	t.mu.Lock()
	t.spans = append(t.spans, s)
	t.mu.Unlock()
	return s
}

func (t *RequestTrace) AddSpan(s *Span) *Span {
	if s == nil {
		return nil
	}
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	t.mu.Lock()
	t.spans = append(t.spans, s)
	t.mu.Unlock()
	return s
}

func (t *RequestTrace) Spans() []*Span {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*Span, len(t.spans))
	copy(out, t.spans)
	return out
}

func (t *RequestTrace) End() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.endedAt.IsZero() {
		t.endedAt = time.Now()
	}
}

func (t *RequestTrace) EndedAt() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.endedAt
}

func (t *RequestTrace) ObserveLLMUsage(u *adapter.CanonicalUsage) {
	if u == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.spans) - 1; i >= 0; i-- {
		if t.spans[i].Type == SpanLLM {
			t.spans[i].ObserveUsage(u)
			return
		}
	}
}

func (t *RequestTrace) ObserveLLMResult(model, finishReason string) {
	if model == "" && finishReason == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.spans) - 1; i >= 0; i-- {
		if t.spans[i].Type == SpanLLM {
			t.spans[i].SetLLMResult(model, finishReason)
			return
		}
	}
}

func (t *RequestTrace) ObserveLLMTurnID(turnID string) {
	if turnID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.spans) - 1; i >= 0; i-- {
		if t.spans[i].Type == SpanLLM {
			t.spans[i].SetTurnID(turnID)
			return
		}
	}
}

func (t *RequestTrace) LLMUsage() *adapter.CanonicalUsage {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := len(t.spans) - 1; i >= 0; i-- {
		if t.spans[i].Type != SpanLLM {
			continue
		}
		if u := t.spans[i].Usage(); u != nil {
			return u
		}
	}
	return nil
}
