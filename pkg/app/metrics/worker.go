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
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/valuecopy"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	taskChanCapacity      = 1000
	workerShutdownTimeout = 5 * time.Second

	droppedEventsMetric = "agentgateway.telemetry.dropped_events"
	dropReasonClosed    = "closed"
	dropReasonQueueFull = "queue_full"
	dropReasonPanic     = "panic"
)

//go:generate mockery --name=Worker --dir=. --output=./mocks --filename=worker_mock.go --case=underscore --with-expecter
type Worker interface {
	StartWorkers(n int)
	Shutdown()
	Process(
		requestTrace *trace.RequestTrace,
		req *infracontext.RequestContext,
		resp *infracontext.ResponseContext,
		startTime time.Time,
		endTime time.Time,
		exporters []telemetrydomain.ExporterConfig,
	)
}

var _ Worker = (*worker)(nil)

type worker struct {
	logger   *slog.Logger
	pipeline *Pipeline
	taskChan chan func()
	closed   atomic.Bool
	enqueue  sync.RWMutex
	wg       sync.WaitGroup
	stop     chan struct{}
	dropped  metric.Int64Counter
}

func NewWorker(logger *slog.Logger, pipeline *Pipeline) Worker {
	dropped, err := otel.Meter("trustgate/metrics").Int64Counter(
		droppedEventsMetric,
		metric.WithDescription("telemetry events dropped after shutdown, when the worker queue is full or on a task panic"),
	)
	if err != nil {
		logger.Warn("failed to create dropped-events counter, drops will only be logged",
			slog.String("component", "metrics"), slog.String("error", err.Error()))
		dropped = nil
	}
	return &worker{
		logger:   logger,
		pipeline: pipeline,
		taskChan: make(chan func(), taskChanCapacity),
		stop:     make(chan struct{}),
		dropped:  dropped,
	}
}

func (w *worker) StartWorkers(n int) {
	for i := 0; i < n; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for task := range w.taskChan {
				w.runTask(task)
			}
		}()
	}
}

func (w *worker) Shutdown() {
	w.enqueue.Lock()
	if w.closed.Swap(true) {
		w.enqueue.Unlock()
		return
	}
	close(w.taskChan)
	close(w.stop)
	w.enqueue.Unlock()
	w.logger.Info(bootlog.MetricsWorkersShuttingDown)

	stopped := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(stopped)
	}()
	timer := time.NewTimer(workerShutdownTimeout)
	defer timer.Stop()
	select {
	case <-stopped:
	case <-timer.C:
		w.logger.Warn("metrics workers did not stop before shutdown timeout")
	}
	if w.pipeline != nil {
		w.pipeline.close()
	}

	w.logger.Info(bootlog.MetricsWorkersStopped)
}

func (w *worker) runTask(task func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		w.recordDrop(dropReasonPanic)
		w.logger.Error("metrics task panicked, dropping event",
			slog.String("component", "metrics"),
			slog.Any("panic", r),
			slog.String("stack", string(debug.Stack())),
		)
	}()
	task()
}

func (w *worker) Process(
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime,
	endTime time.Time,
	exporters []telemetrydomain.ExporterConfig,
) {
	if req == nil || resp == nil {
		return
	}
	ownedExporters := make([]telemetrydomain.ExporterConfig, len(exporters))
	for i, exporter := range exporters {
		ownedExporters[i] = exporter
		if exporter.Settings != nil {
			ownedExporters[i].Settings = valuecopy.Deep(exporter.Settings).(map[string]interface{})
		}
	}
	w.enqueueTask(func() {
		w.pipeline.publishContext(workerContext{done: w.stop}, requestTrace, req, resp, startTime, endTime, ownedExporters)
	}, req.GatewayID)
}

type workerContext struct {
	done <-chan struct{}
}

func (c workerContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c workerContext) Done() <-chan struct{}       { return c.done }
func (c workerContext) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}
func (c workerContext) Value(any) any { return nil }

func (w *worker) enqueueTask(task func(), gatewayID string) {
	w.enqueue.RLock()
	defer w.enqueue.RUnlock()
	if w.closed.Load() {
		w.recordDrop(dropReasonClosed)
		return
	}
	select {
	case w.taskChan <- task:
	default:
		w.recordDrop(dropReasonQueueFull)
		w.logger.Warn("metrics task channel is full, dropping task", slog.String("gateway_id", gatewayID))
	}
}

func (w *worker) recordDrop(reason string) {
	if w.dropped != nil {
		w.dropped.Add(context.Background(), 1, metric.WithAttributes(attribute.String("reason", reason)))
	}
}
