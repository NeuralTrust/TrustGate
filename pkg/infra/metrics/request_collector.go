package metrics

import "sync"

const CollectorKey = "__metrics_collector"

type Config struct {
	EnablePluginTraces  bool
	EnableRequestTraces bool
	ExtraParams         map[string]string
}

type Collector struct {
	traceID string
	mu      sync.Mutex
	events  []*Event
	cfg     *Config
}

func NewCollector(traceID string, cfg *Config) *Collector {
	return &Collector{
		traceID: traceID,
		cfg:     cfg,
	}
}

func (rc *Collector) Emit(evt *Event) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if evt.Type == PluginType && !rc.cfg.EnablePluginTraces {
		return
	}
	if evt.Type == TraceType && !rc.cfg.EnableRequestTraces {
		return
	}

	evt.TraceID = rc.traceID
	evt.Params = rc.cfg.ExtraParams
	rc.events = append(rc.events, evt)
}

func (rc *Collector) Flush() []*Event {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	out := make([]*Event, len(rc.events))
	copy(out, rc.events)
	rc.events = nil
	return out
}
