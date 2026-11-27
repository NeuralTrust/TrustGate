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

const (
	failureLogInterval = time.Minute
	// The OTLP HTTP exporter puts up to 4 MiB of the collector's response body
	// in its error, and a tenant chooses that collector.
	maxLoggedErrorBytes = 512
	maxThrottledErrors  = 64
)

// reportedError marks an export failure the reporting exporter already logged,
// so the global OTel error handler, which the batch processor also hands every
// export error to, does not log it a second time.
type reportedError struct{ err error }

func (e *reportedError) Error() string { return e.err.Error() }

func (e *reportedError) Unwrap() error { return e.err }

func isReported(err error) bool {
	var reported *reportedError
	return errors.As(err, &reported)
}

type reportingExporter struct {
	sdklog.Exporter
	reporter *failureReporter
}

func newReportingExporter(inner sdklog.Exporter, logger *slog.Logger, endpoint string) *reportingExporter {
	return &reportingExporter{
		Exporter: inner,
		reporter: newFailureReporter(logger, redactEndpoint(endpoint), failureLogInterval, time.Now),
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

// failureReporter keeps every log line about one exporter at least interval
// apart, so a collector that keeps failing, or alternates failures and
// successes, costs one line per interval. What it holds back is folded into
// the next line it writes.
type failureReporter struct {
	logger   *slog.Logger
	endpoint string
	interval time.Duration
	now      func() time.Time
	class    atomic.Value

	mu             sync.Mutex
	failing        bool
	recoveryDue    bool
	since          time.Time
	lastLog        time.Time
	lastErr        string
	pendingExports int
	pendingRecords int
	outageRecords  int
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

func (r *failureReporter) canLog(now time.Time) bool {
	return r.lastLog.IsZero() || now.Sub(r.lastLog) >= r.interval
}

func (r *failureReporter) failed(records int, err error) {
	now := r.now()
	r.mu.Lock()
	if !r.failing && !r.recoveryDue {
		r.since = now
		r.outageRecords = 0
	}
	r.failing = true
	r.recoveryDue = false
	r.lastErr = truncateError(err.Error())
	r.pendingExports++
	r.pendingRecords += records
	r.outageRecords += records
	if !r.canLog(now) {
		r.mu.Unlock()
		return
	}
	attrs := r.takeFailureAttrs(now)
	r.mu.Unlock()
	r.logger.Warn("otlp export failed; records dropped", attrs...)
}

func (r *failureReporter) succeeded() {
	now := r.now()
	r.mu.Lock()
	if !r.failing && !r.recoveryDue {
		r.mu.Unlock()
		return
	}
	r.failing = false
	r.recoveryDue = true
	if !r.canLog(now) {
		r.mu.Unlock()
		return
	}
	attrs := r.takeRecoveryAttrs(now)
	r.mu.Unlock()
	r.logger.Info("otlp export recovered", attrs...)
}

// flush writes whatever the interval held back. It runs when the exporter
// closes, since no later export will carry it.
func (r *failureReporter) flush() {
	now := r.now()
	r.mu.Lock()
	var failure, recovery []any
	if r.pendingExports > 0 {
		failure = r.takeFailureAttrs(now)
	}
	if r.recoveryDue {
		recovery = r.takeRecoveryAttrs(now)
	}
	r.mu.Unlock()
	if failure != nil {
		r.logger.Warn("otlp export failed; records dropped", failure...)
	}
	if recovery != nil {
		r.logger.Info("otlp export recovered", recovery...)
	}
}

func (r *failureReporter) takeFailureAttrs(now time.Time) []any {
	attrs := []any{
		slog.String("endpoint", r.endpoint),
		slog.String("class", r.dataClass()),
		slog.Int("failed_exports", r.pendingExports),
		slog.Int("dropped_records", r.pendingRecords),
		slog.String("failing_for", roundDuration(now.Sub(r.since))),
		slog.String("error", r.lastErr),
	}
	r.pendingExports, r.pendingRecords = 0, 0
	r.lastLog = now
	return attrs
}

func (r *failureReporter) takeRecoveryAttrs(now time.Time) []any {
	attrs := []any{
		slog.String("endpoint", r.endpoint),
		slog.String("class", r.dataClass()),
		slog.String("failing_for", roundDuration(now.Sub(r.since))),
		slog.Int("dropped_records", r.outageRecords),
	}
	r.recoveryDue = false
	r.pendingExports, r.pendingRecords, r.outageRecords = 0, 0, 0
	r.lastLog = now
	return attrs
}

func roundDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}

func truncateError(s string) string {
	if len(s) <= maxLoggedErrorBytes {
		return s
	}
	return s[:maxLoggedErrorBytes] + "…(truncated)"
}

// redactEndpoint keeps the scheme, host and path of an endpoint and drops any
// user info, query or fragment, which may carry credentials.
func redactEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if !hasScheme(endpoint) {
		u, err := url.Parse("//" + endpoint)
		if err != nil {
			return ""
		}
		return u.Host + u.Path
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

// errorHandler exists because the SDK's default handler prints errors to
// stderr as plain text, which log pipelines that parse JSON drop.
type errorHandler struct {
	logger   *slog.Logger
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]*throttledError
}

type throttledError struct {
	last       time.Time
	suppressed int
}

func newErrorHandler(logger *slog.Logger, interval time.Duration, now func() time.Time) *errorHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &errorHandler{logger: logger, interval: interval, now: now, entries: map[string]*throttledError{}}
}

func (h *errorHandler) Handle(err error) {
	if err == nil || isReported(err) {
		return
	}
	msg := truncateError(err.Error())
	now := h.now()
	h.mu.Lock()
	entry, ok := h.entries[msg]
	if !ok {
		if len(h.entries) >= maxThrottledErrors {
			h.evictExpired(now)
		}
		if len(h.entries) >= maxThrottledErrors {
			h.mu.Unlock()
			return
		}
		entry = &throttledError{}
		h.entries[msg] = entry
	}
	if !entry.last.IsZero() && now.Sub(entry.last) < h.interval {
		entry.suppressed++
		h.mu.Unlock()
		return
	}
	suppressed := entry.suppressed
	entry.suppressed = 0
	entry.last = now
	h.mu.Unlock()
	attrs := []any{slog.String("error", msg)}
	if suppressed > 0 {
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}
	h.logger.Warn("opentelemetry sdk error", attrs...)
}

func (h *errorHandler) evictExpired(now time.Time) {
	for msg, entry := range h.entries {
		if now.Sub(entry.last) >= h.interval {
			delete(h.entries, msg)
		}
	}
}

// InstallErrorHandler makes logger the destination of every error the OTel SDK
// reports through its global handler, such as failed trace and metric exports.
// Each distinct error is logged at most once per minute.
func InstallErrorHandler(logger *slog.Logger) {
	otel.SetErrorHandler(newErrorHandler(logger, failureLogInterval, time.Now))
}
