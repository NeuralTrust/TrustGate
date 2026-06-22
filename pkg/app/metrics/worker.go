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
	"sync"
	"sync/atomic"
	"time"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	taskChanCapacity = 1000
	// shutdownWaitTimeout bounds how long Shutdown waits for in-flight tasks
	// before closing the exporter, so a stuck task can never hang shutdown.
	shutdownWaitTimeout = 10 * time.Second
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
	ctx      context.Context
	cancel   context.CancelFunc
	closed   atomic.Bool
	wg       sync.WaitGroup
}

func NewWorker(logger *slog.Logger, pipeline *Pipeline) Worker {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- cancel is stored in the struct and called in Shutdown()
	return &worker{
		logger:   logger,
		pipeline: pipeline,
		taskChan: make(chan func(), taskChanCapacity),
		ctx:      ctx,
		cancel:   cancel,
	}
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
// closes the exporter. Waiting on the worker goroutines guarantees no task is
// still using the exporter when it is closed.
func (w *worker) Shutdown() {
	w.closed.Store(true)
	w.logger.Info("shutting down metrics workers")

	w.cancel()
	if !w.waitForWorkers(shutdownWaitTimeout) {
		w.logger.Warn("metrics workers did not stop in time, closing exporter anyway",
			slog.Duration("timeout", shutdownWaitTimeout))
	}
	w.drainPendingTasks()
	w.pipeline.close()

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
	w.enqueueTask(func() {
		w.pipeline.publish(requestTrace, req, resp, startTime, endTime, exporters)
	}, req.GatewayID)
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
