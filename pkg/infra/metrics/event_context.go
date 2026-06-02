package metrics

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
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
