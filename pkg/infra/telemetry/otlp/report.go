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

package otlp

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
)

const failureWarnInterval = time.Minute

// reportedError marks an export failure the reporting exporter already logged,
// so the global OTel error handler, which the batch processor also hands every
// export error to, does not log it a second time.
type reportedError struct{ err error }

func (e *reportedError) Error() string { return e.err.Error() }

func (e *reportedError) Unwrap() error { return e.err }

// reportingExporter logs export failures through slog. The batch processor
// exports in the background and only hands failures to the OTel global error
// handler, so without it a dead collector leaves no structured log line.
type reportingExporter struct {
	sdklog.Exporter
	reporter *failureReporter
}

func newReportingExporter(inner sdklog.Exporter, logger *slog.Logger, endpoint string) *reportingExporter {
	return &reportingExporter{
		Exporter: inner,
		reporter: newFailureReporter(logger, redactEndpoint(endpoint), failureWarnInterval, time.Now),
	}
}

func (e *reportingExporter) Export(ctx context.Context, records []sdklog.Record) error {
	err := e.Exporter.Export(ctx, records)
	if len(records) == 0 {
		return err
	}
	if err != nil {
		e.reporter.failed(len(records), err)
		return &reportedError{err: err}
	}
	e.reporter.succeeded()
	return nil
}

// failureReporter logs the first failure of a streak at once, then at most one
// summary per interval, and the recovery when an export succeeds again.
type failureReporter struct {
	logger   *slog.Logger
	endpoint string
	interval time.Duration
	now      func() time.Time
	class    atomic.Value

	mu             sync.Mutex
	failing        bool
	since          time.Time
	lastWarn       time.Time
	pendingBatches int
	pendingRecords int
	streakRecords  int
}

func newFailureReporter(logger *slog.Logger, endpoint string, interval time.Duration, now func() time.Time) *failureReporter {
	if logger == nil {
		logger = slog.Default()
	}
	r := &failureReporter{logger: logger, endpoint: endpoint, interval: interval, now: now}
	r.class.Store(metrics.Metadata)
	return r
}

func (r *failureReporter) setDataClass(class metrics.DataClass) {
	r.class.Store(class)
}

func (r *failureReporter) dataClass() string {
	class, _ := r.class.Load().(metrics.DataClass)
	return string(class)
}

func (r *failureReporter) failed(records int, err error) {
	now := r.now()
	r.mu.Lock()
	if !r.failing {
		r.failing = true
		r.since = now
		r.lastWarn = now
		r.streakRecords = records
		r.mu.Unlock()
		r.logger.Warn("otlp export failed; records dropped",
			slog.String("endpoint", r.endpoint),
			slog.String("class", r.dataClass()),
			slog.Int("dropped_records", records),
			slog.String("error", err.Error()))
		return
	}
	r.streakRecords += records
	r.pendingBatches++
	r.pendingRecords += records
	if now.Sub(r.lastWarn) < r.interval {
		r.mu.Unlock()
		return
	}
	batches, dropped := r.pendingBatches, r.pendingRecords
	r.pendingBatches, r.pendingRecords = 0, 0
	r.lastWarn = now
	failingFor := now.Sub(r.since)
	r.mu.Unlock()
	r.logger.Warn("otlp export still failing; records dropped",
		slog.String("endpoint", r.endpoint),
		slog.String("class", r.dataClass()),
		slog.Int("failed_batches", batches),
		slog.Int("dropped_records", dropped),
		slog.String("failing_for", roundDuration(failingFor)),
		slog.String("error", err.Error()))
}

func (r *failureReporter) succeeded() {
	now := r.now()
	r.mu.Lock()
	if !r.failing {
		r.mu.Unlock()
		return
	}
	failingFor, dropped := now.Sub(r.since), r.streakRecords
	r.failing = false
	r.pendingBatches, r.pendingRecords, r.streakRecords = 0, 0, 0
	r.mu.Unlock()
	r.logger.Info("otlp export recovered",
		slog.String("endpoint", r.endpoint),
		slog.String("class", r.dataClass()),
		slog.String("failing_for", roundDuration(failingFor)),
		slog.Int("dropped_records", dropped))
}

func roundDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

// redactEndpoint keeps the scheme, host and path of an endpoint URL and drops
// any user info, query or fragment, which may carry credentials.
func redactEndpoint(endpoint string) string {
	if !hasScheme(endpoint) {
		return endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// errorHandler routes OTel SDK errors to slog at most once per interval. The
// SDK's default handler prints them to stderr as plain text, which log
// pipelines that parse JSON drop.
type errorHandler struct {
	logger   *slog.Logger
	interval time.Duration
	now      func() time.Time

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func newErrorHandler(logger *slog.Logger, interval time.Duration, now func() time.Time) *errorHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &errorHandler{logger: logger, interval: interval, now: now}
}

func (h *errorHandler) Handle(err error) {
	if err == nil {
		return
	}
	var reported *reportedError
	if errors.As(err, &reported) {
		return
	}
	now := h.now()
	h.mu.Lock()
	if !h.last.IsZero() && now.Sub(h.last) < h.interval {
		h.suppressed++
		h.mu.Unlock()
		return
	}
	suppressed := h.suppressed
	h.suppressed = 0
	h.last = now
	h.mu.Unlock()
	attrs := []any{slog.String("error", err.Error())}
	if suppressed > 0 {
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}
	h.logger.Warn("opentelemetry sdk error", attrs...)
}

// InstallErrorHandler makes logger the destination of every error the OTel SDK
// reports through its global handler, such as failed trace and metric exports.
func InstallErrorHandler(logger *slog.Logger) {
	otel.SetErrorHandler(newErrorHandler(logger, failureWarnInterval, time.Now))
}
