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

package metrics

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

type EventContext struct {
	span *trace.Span
}

func NewEventContext(span *trace.Span) *EventContext {
	return &EventContext{span: span}
}

func (e *EventContext) SetExtras(extras any) {
	if e == nil || e.span == nil {
		return
	}
	e.span.SetExtras(extras)
}

func (e *EventContext) SetError(err error) {
	if e == nil || e.span == nil || err == nil {
		return
	}
	e.span.SetError(err.Error())
}

func (e *EventContext) SetStatusCode(code int) {
	if e == nil || e.span == nil {
		return
	}
	e.span.SetStatusCode(code)
}

func (e *EventContext) SetSLatency(duration time.Duration) {
	if e == nil || e.span == nil {
		return
	}
	e.span.SetLatency(duration)
}

func (e *EventContext) SetMode(mode string) {
	if e == nil || e.span == nil {
		return
	}
	e.span.SetMode(mode)
}

func (e *EventContext) SetDecision(decision string) {
	if e == nil || e.span == nil {
		return
	}
	e.span.SetDecision(decision)
}

// SetScore records the detection score and its label on the metrics span. The
// label is what the analytics Security Engine breakdown groups by, so security
// plugins should pass the detected category (e.g. the moderation category or the
// guard signal type) rather than a plugin-internal identifier.
func (e *EventContext) SetScore(score float64, label string) {
	if e == nil || e.span == nil {
		return
	}
	e.span.SetScore(score, label)
}

func (e *EventContext) HasDecision() bool {
	if e == nil || e.span == nil {
		return false
	}
	return e.span.HasDecision()
}

func (e *EventContext) Publish() {
	if e == nil || e.span == nil {
		return
	}
	e.span.End()
}
