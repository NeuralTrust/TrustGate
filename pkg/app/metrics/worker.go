package metrics

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	apptelemetry "github.com/NeuralTrust/AgentGateway/pkg/app/telemetry"
	domaintelemetry "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
)

const (
	taskChanCapacity = 1000
	// shutdownWaitTimeout bounds how long Shutdown waits for in-flight tasks
	// before closing exporters, so a stuck task can never hang shutdown.
	shutdownWaitTimeout = 10 * time.Second
)

//go:generate mockery --name=Worker --dir=. --output=./mocks --filename=worker_mock.go --case=underscore --with-expecter
type Worker interface {
	StartWorkers(n int)
	Shutdown()
	HasDefaultExporters() bool
	Process(
		exporters []domaintelemetry.ExporterConfig,
		requestTrace *trace.RequestTrace,
		req *infracontext.RequestContext,
		resp *infracontext.ResponseContext,
		startTime time.Time,
		endTime time.Time,
	)
}

var _ Worker = (*worker)(nil)

type worker struct {
	logger           *slog.Logger
	exportersBuilder apptelemetry.ExportersBuilder
	defaultExporters []apptelemetry.Exporter
	taskChan         chan func()
	ctx              context.Context
	cancel           context.CancelFunc
	closed           atomic.Bool
	wg               sync.WaitGroup
	exporterCache    sync.Map
}

func NewWorker(
	logger *slog.Logger,
	exportersBuilder apptelemetry.ExportersBuilder,
	defaultExporters []apptelemetry.Exporter,
) Worker {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- cancel is stored in the struct and called in Shutdown()
	return &worker{
		logger:           logger,
		exportersBuilder: exportersBuilder,
		defaultExporters: defaultExporters,
		taskChan:         make(chan func(), taskChanCapacity),
		ctx:              ctx,
		cancel:           cancel,
	}
}

func (w *worker) HasDefaultExporters() bool {
	return len(w.defaultExporters) > 0
}

func (w *worker) StartWorkers(n int) {
	for i := 0; i < n; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for {
				select {
				case task := <-w.taskChan:
					task()
				case <-w.ctx.Done():
					return
				}
			}
		}()
	}
}

// Shutdown stops accepting new tasks, waits for in-flight tasks to finish, and
// closes every exporter. Waiting on the worker goroutines guarantees no task is
// still using an exporter when it is closed.
func (w *worker) Shutdown() {
	w.closed.Store(true)
	w.logger.Info("shutting down metrics workers")

	w.cancel()
	if !w.waitForWorkers(shutdownWaitTimeout) {
		w.logger.Warn("metrics workers did not stop in time, closing exporters anyway",
			slog.Duration("timeout", shutdownWaitTimeout))
	}
	w.drainPendingTasks()
	w.closeExporters()

	w.logger.Info("metrics workers stopped")
}

// waitForWorkers waits for the worker goroutines to exit, returning false if the
// timeout elapses first.
func (w *worker) waitForWorkers(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// drainPendingTasks runs any tasks still buffered in the channel so events
// enqueued by in-flight requests are not silently dropped on shutdown.
func (w *worker) drainPendingTasks() {
	for {
		select {
		case task := <-w.taskChan:
			task()
		default:
			return
		}
	}
}

func (w *worker) closeExporters() {
	w.exporterCache.Range(func(key, value interface{}) bool {
		if exporters, ok := value.([]apptelemetry.Exporter); ok {
			closeExporters(exporters)
		}
		w.exporterCache.Delete(key)
		return true
	})
	closeExporters(w.defaultExporters)
}

func (w *worker) Process(
	exporters []domaintelemetry.ExporterConfig,
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime,
	endTime time.Time,
) {
	if req == nil || resp == nil {
		return
	}
	w.enqueueTask(func() {
		w.export(exporters, requestTrace, req, resp, startTime, endTime)
	}, req.GatewayID)
}

func (w *worker) export(
	exporters []domaintelemetry.ExporterConfig,
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime,
	endTime time.Time,
) {
	targets := w.resolveExporters(exporters)
	if len(targets) == 0 {
		return
	}

	events := projectTrace(requestTrace)
	if len(events) == 0 {
		if requestTrace != nil && !requestTrace.RequestTracesEnabled() {
			return
		}
		base := metric_events.NewTraceEvent()
		stampTrace(base, requestTrace)
		events = []*metric_events.Event{base}
	}

	exchange := exchangeFrom(req, resp, startTime, endTime)
	for _, evt := range events {
		evt.Feed(exchange)
	}

	w.dispatch(targets, events, req.GatewayID)
}

// projectTrace turns the request trace into the wire-format events the
// exporters consume. Every span (downstream call or plugin) becomes one event
// correlated by trace id, gated by the trace's telemetry flags.
func projectTrace(requestTrace *trace.RequestTrace) []*metric_events.Event {
	if requestTrace == nil {
		return nil
	}
	var events []*metric_events.Event
	for _, span := range requestTrace.Spans() {
		switch span.Type {
		case trace.SpanPlugin:
			if !requestTrace.PluginTracesEnabled() {
				continue
			}
			events = append(events, projectPluginSpan(requestTrace, span))
		default:
			if !requestTrace.RequestTracesEnabled() {
				continue
			}
			events = append(events, projectCallSpan(requestTrace, span))
		}
	}
	return events
}

func projectCallSpan(requestTrace *trace.RequestTrace, span *trace.Span) *metric_events.Event {
	evt := metric_events.NewTraceEvent()
	if attrs, ok := span.LLMAttrsCopy(); ok {
		evt.Attempt = attrs.Attempt
		evt.Fallback = attrs.Fallback
		evt.BackendID = attrs.BackendID
		evt.Outcome = attrs.Outcome
		if evt.Upstream != nil {
			evt.Upstream.Target.Provider = attrs.Provider
			evt.Upstream.Target.Latency = span.Latency().Milliseconds()
		}
		evt.Usage = metric_events.UsageEventFromCanonical(attrs.Usage)
	}
	evt.StatusCode = span.StatusCode()
	stampTrace(evt, requestTrace)
	return evt
}

func projectPluginSpan(requestTrace *trace.RequestTrace, span *trace.Span) *metric_events.Event {
	attrs := span.PluginAttrsCopy()
	errMsg := span.Error()
	evt := metric_events.NewPluginEvent()
	evt.Plugin = &metric_events.PluginDataEvent{
		PluginName:   span.Name,
		Stage:        attrs.Stage,
		Mode:         attrs.Mode,
		Decision:     attrs.Decision,
		Extras:       attrs.Extras,
		Error:        errMsg != "",
		ErrorMessage: errMsg,
		StatusCode:   span.StatusCode(),
		Latency:      span.Latency().Microseconds(),
		LatencyUnit:  "μs",
	}
	stampTrace(evt, requestTrace)
	return evt
}

func stampTrace(evt *metric_events.Event, requestTrace *trace.RequestTrace) {
	if requestTrace == nil {
		return
	}
	evt.TraceID = requestTrace.TraceID()
	evt.FingerprintID = requestTrace.Metadata().FingerprintID
}

// resolveExporters returns the default exporters (minus those overridden by an
// explicit config) plus the per-request exporters, building and caching the
// latter on first use.
func (w *worker) resolveExporters(exporters []domaintelemetry.ExporterConfig) []apptelemetry.Exporter {
	explicitNames := make(map[string]struct{}, len(exporters))
	for _, dto := range exporters {
		explicitNames[dto.Name] = struct{}{}
	}

	var resolved []apptelemetry.Exporter
	for _, d := range w.defaultExporters {
		if _, overridden := explicitNames[d.Name()]; !overridden {
			resolved = append(resolved, d)
		}
	}

	if len(exporters) == 0 {
		return resolved
	}

	cacheKey := createExportersCacheKey(exporters)
	if cached, found := w.exporterCache.Load(cacheKey); found {
		if exp, ok := cached.([]apptelemetry.Exporter); ok {
			return append(resolved, exp...)
		}
		w.logger.Error("cached exporter is not of expected type")
		return resolved
	}

	built, err := w.exportersBuilder.Build(exporters)
	if err != nil {
		w.logger.Error("failed to build telemetry exporters", slog.String("error", err.Error()))
		return resolved
	}

	// Another goroutine may have built the same set concurrently; keep the
	// stored instance and close ours to avoid leaking producers.
	if actual, loaded := w.exporterCache.LoadOrStore(cacheKey, built); loaded {
		closeExporters(built)
		built, _ = actual.([]apptelemetry.Exporter)
	}
	return append(resolved, built...)
}

func closeExporters(exporters []apptelemetry.Exporter) {
	for _, exp := range exporters {
		exp.Close()
	}
}

func (w *worker) dispatch(exporters []apptelemetry.Exporter, events []*metric_events.Event, gatewayID string) {
	var failed []string
	for _, exporter := range exporters {
		if err := w.handleEvents(exporter, events); err != nil {
			w.logger.Error("exporter failed to handle metrics event",
				slog.String("gateway_id", gatewayID),
				slog.String("exporter", exporter.Name()),
				slog.String("error", err.Error()),
			)
			failed = append(failed, exporter.Name())
		}
	}
	if len(failed) > 0 {
		w.logger.Warn("some exporters failed to handle metrics events",
			slog.Int("failed", len(failed)),
			slog.Any("exporters", failed),
		)
	}
}

func (w *worker) handleEvents(exporter apptelemetry.Exporter, events []*metric_events.Event) error {
	for _, evt := range events {
		if err := exporter.Handle(context.Background(), *evt); err != nil {
			return err
		}
	}
	return nil
}

func (w *worker) enqueueTask(task func(), gatewayID string) {
	if w.closed.Load() {
		return
	}
	select {
	case w.taskChan <- task:
	default:
		w.logger.Warn("metrics task channel is full, dropping task", slog.String("gateway_id", gatewayID))
	}
}

func exchangeFrom(
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime, endTime time.Time,
) metric_events.Exchange {
	return metric_events.Exchange{
		GatewayID:       req.GatewayID,
		SessionID:       req.SessionID,
		Method:          req.Method,
		Path:            req.Path,
		IP:              req.IP,
		RequestHeaders:  req.Headers,
		ResponseHeaders: resp.Headers,
		RequestBody:     req.Body,
		ResponseBody:    resp.Body,
		StatusCode:      resp.StatusCode,
		Streaming:       resp.Streaming,
		TargetLatency:   resp.TargetLatency,
		StartTime:       startTime,
		EndTime:         endTime,
	}
}

func createExportersCacheKey(exporters []domaintelemetry.ExporterConfig) string {
	data, err := json.Marshal(exporters)
	if err != nil {
		var key string
		for _, exp := range exporters {
			key += exp.Name + ":"
		}
		return key
	}
	return string(data)
}
