package metrics

import (
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type EventContext struct {
	PluginName string
	Stage      string
	data       *metric_events.PluginDataEvent
	collector  *Collector
	mu         sync.Mutex
}

func NewEventContext(pluginName, stage string, collector *Collector) *EventContext {
	return &EventContext{
		PluginName: pluginName,
		Stage:      stage,
		data: &metric_events.PluginDataEvent{
			PluginName: pluginName,
			Stage:      stage,
		},
		collector: collector,
	}
}

func (e *EventContext) SetExtras(extras interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data.Extras = extras
}

func (e *EventContext) SetError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data.Error = true
	e.data.ErrorMessage = err.Error()
}

func (e *EventContext) SetStatusCode(code int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data.StatusCode = code
}

func (e *EventContext) Publish() {
	e.mu.Lock()
	defer e.mu.Unlock()
	evt := metric_events.NewPluginEvent()
	evt.Plugin = e.data
	e.collector.Emit(evt)
}
