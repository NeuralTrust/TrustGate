package metrics

import (
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
)

type EventContext struct {
	PluginName string
	Stage      string
	data       *metric_events.PluginDataEvent
	collector  *Collector
	mu         sync.Mutex
	mode       string
	decision   string
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

func (e *EventContext) SetSLatency(duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data.Latency = duration.Microseconds()
	e.data.LatencyUnit = "μs"
}

func (e *EventContext) SetMode(mode plugintypes.Option) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = string(mode)
}

func (e *EventContext) SetDecision(decision plugintypes.Decision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.decision = string(decision)
}

func (e *EventContext) HasDecision() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.decision != ""
}

func (e *EventContext) Publish() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data.Mode = e.mode
	e.data.Decision = e.decision
	evt := metric_events.NewPluginEvent()
	evt.Plugin = e.data
	e.collector.Emit(evt)
}
