package metrics

import (
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/google/uuid"
)

type contextKey string

const CollectorKey contextKey = "__metrics_collector"

type Config struct {
	EnablePluginTraces  bool
	EnableRequestTraces bool
	ExtraParams         map[string]string
}

type Collector struct {
	traceID string
	mu      sync.Mutex
	events  []*metric_events.Event
	cfg     *Config
}

func NewCollector(traceID string, cfg *Config) *Collector {
	if traceID == "" {
		traceID = uuid.New().String()
	}
	return &Collector{
		traceID: traceID,
		cfg:     cfg,
	}
}

func (rc *Collector) Emit(evt *metric_events.Event) {
	if rc.cfg == nil {
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if evt.Type == metric_events.PluginType && !rc.cfg.EnablePluginTraces {
		return
	}
	if evt.Type == metric_events.TraceType && !rc.cfg.EnableRequestTraces {
		return
	}

	evt.TraceID = rc.traceID
	evt.Params = rc.cfg.ExtraParams
	rc.events = append(rc.events, evt)
}

func (rc *Collector) Flush() []*metric_events.Event {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	out := make([]*metric_events.Event, len(rc.events))
	copy(out, rc.events)
	rc.events = nil
	return out
}

func (rc *Collector) GetEvents() []*metric_events.Event {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	out := make([]*metric_events.Event, len(rc.events))
	copy(out, rc.events)
	return out
}
