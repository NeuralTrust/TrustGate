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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	msgExportFailed    = "otlp export failed; records dropped"
	msgExportRecovered = "otlp export recovered"
)

type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *logSink) lines(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(s.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		out = append(out, entry)
	}
	return out
}

func newSinkLogger() (*slog.Logger, *logSink) {
	sink := &logSink{}
	return slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug})), sink
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type stubExporter struct {
	sdklog.Exporter
	err error
}

func (e *stubExporter) Export(context.Context, []sdklog.Record) error { return e.err }

func newTestReportingExporter(inner sdklog.Exporter, logger *slog.Logger, clock *fakeClock) *reportingExporter {
	return &reportingExporter{
		Exporter: inner,
		reporter: newFailureReporter(logger, "https://collector.example:4318/v1/logs", time.Minute, clock.now),
	}
}

func records(n int) []sdklog.Record {
	return make([]sdklog.Record, n)
}

func TestReportingExporter_FirstFailureLogsWarnAndMarksError(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	cause := errors.New("connection refused")
	exp := newTestReportingExporter(&stubExporter{err: cause}, logger, &fakeClock{t: time.Unix(0, 0)})

	err := exp.Export(context.Background(), records(3))

	require.ErrorIs(t, err, cause)
	assert.True(t, isReported(err))
	lines := sink.lines(t)
	require.Len(t, lines, 1)
	assert.Equal(t, "WARN", lines[0]["level"])
	assert.Equal(t, msgExportFailed, lines[0]["msg"])
	assert.Equal(t, "https://collector.example:4318/v1/logs", lines[0]["endpoint"])
	assert.Equal(t, "metadata", lines[0]["class"])
	assert.EqualValues(t, 1, lines[0]["failed_exports"])
	assert.EqualValues(t, 3, lines[0]["dropped_records"])
	assert.Equal(t, "0s", lines[0]["failing_for"])
	assert.Equal(t, "connection refused", lines[0]["error"])
}

func TestReportingExporter_ThrottlesAStreakToOneLinePerInterval(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	clock := &fakeClock{t: time.Unix(0, 0)}
	exp := newTestReportingExporter(&stubExporter{err: errors.New("timeout")}, logger, clock)

	_ = exp.Export(context.Background(), records(2))
	for range 4 {
		clock.advance(10 * time.Second)
		_ = exp.Export(context.Background(), records(5))
	}
	require.Len(t, sink.lines(t), 1)

	clock.advance(30 * time.Second)
	_ = exp.Export(context.Background(), records(5))

	lines := sink.lines(t)
	require.Len(t, lines, 2)
	assert.Equal(t, msgExportFailed, lines[1]["msg"])
	assert.EqualValues(t, 5, lines[1]["failed_exports"])
	assert.EqualValues(t, 25, lines[1]["dropped_records"])
	assert.Equal(t, "1m10s", lines[1]["failing_for"])
}

func TestReportingExporter_AlternatingOutcomesStayWithinTheInterval(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	clock := &fakeClock{t: time.Unix(0, 0)}
	stub := &stubExporter{}
	exp := newTestReportingExporter(stub, logger, clock)

	for i := range 120 {
		if i%2 == 0 {
			stub.err = errors.New("503")
		} else {
			stub.err = nil
		}
		_ = exp.Export(context.Background(), records(1))
		clock.advance(time.Second)
	}

	lines := sink.lines(t)
	require.Len(t, lines, 2, "120 exports over two minutes must log one line per minute")
	assert.Equal(t, msgExportFailed, lines[0]["msg"])
	assert.Equal(t, msgExportFailed, lines[1]["msg"])
	assert.EqualValues(t, 30, lines[1]["failed_exports"])
	assert.Equal(t, "1m0s", lines[1]["failing_for"])
}

func TestReportingExporter_LogsRecoveryWithOutageTotals(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	clock := &fakeClock{t: time.Unix(0, 0)}
	stub := &stubExporter{err: errors.New("503")}
	exp := newTestReportingExporter(stub, logger, clock)

	_ = exp.Export(context.Background(), records(2))
	clock.advance(5 * time.Second)
	_ = exp.Export(context.Background(), records(4))
	stub.err = nil
	clock.advance(5 * time.Second)
	require.NoError(t, exp.Export(context.Background(), records(1)))
	require.Len(t, sink.lines(t), 1, "a recovery inside the interval waits")

	clock.advance(time.Minute)
	require.NoError(t, exp.Export(context.Background(), records(1)))
	require.NoError(t, exp.Export(context.Background(), records(1)))

	lines := sink.lines(t)
	require.Len(t, lines, 2)
	assert.Equal(t, "INFO", lines[1]["level"])
	assert.Equal(t, msgExportRecovered, lines[1]["msg"])
	assert.EqualValues(t, 6, lines[1]["dropped_records"])
	assert.Equal(t, "1m10s", lines[1]["failing_for"])
}

func TestReportingExporter_SuccessAndEmptyBatchesStaySilent(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	stub := &stubExporter{err: errors.New("down")}
	exp := newTestReportingExporter(stub, logger, &fakeClock{t: time.Unix(0, 0)})

	err := exp.Export(context.Background(), nil)
	require.Error(t, err)
	assert.False(t, isReported(err), "an empty batch reports nothing, so its error is not marked")

	stub.err = nil
	require.NoError(t, exp.Export(context.Background(), records(2)))

	assert.Empty(t, sink.lines(t))
}

func TestFailureReporter_FlushWritesWhatTheIntervalHeldBack(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	clock := &fakeClock{t: time.Unix(0, 0)}
	stub := &stubExporter{err: errors.New("refused")}
	exp := newTestReportingExporter(stub, logger, clock)

	_ = exp.Export(context.Background(), records(1))
	clock.advance(10 * time.Second)
	_ = exp.Export(context.Background(), records(7))
	stub.err = nil
	clock.advance(time.Second)
	_ = exp.Export(context.Background(), records(1))
	exp.reporter.flush()
	exp.reporter.flush()

	lines := sink.lines(t)
	require.Len(t, lines, 3)
	assert.Equal(t, msgExportFailed, lines[1]["msg"])
	assert.EqualValues(t, 7, lines[1]["dropped_records"])
	assert.Equal(t, msgExportRecovered, lines[2]["msg"])
	assert.EqualValues(t, 8, lines[2]["dropped_records"])
}

func TestReportingExporter_TruncatesLongErrors(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	body := strings.Repeat("x", 4096)
	exp := newTestReportingExporter(&stubExporter{err: errors.New("body: " + body)}, logger, &fakeClock{t: time.Unix(0, 0)})

	_ = exp.Export(context.Background(), records(1))

	lines := sink.lines(t)
	require.Len(t, lines, 1)
	logged, _ := lines[0]["error"].(string)
	assert.Less(t, len(logged), 600)
	assert.True(t, strings.HasSuffix(logged, "(truncated)"))
}

func TestErrorHandler_SkipsErrorsTheExporterAlreadyLogged(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	h := newErrorHandler(logger, time.Minute, (&fakeClock{t: time.Unix(0, 0)}).now)

	h.Handle(&reportedError{err: errors.New("already logged")})
	h.Handle(fmt.Errorf("joined: %w", &reportedError{err: errors.New("already logged")}))
	h.Handle(nil)

	assert.Empty(t, sink.lines(t))
}

func TestErrorHandler_ThrottlesEachDistinctError(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	clock := &fakeClock{t: time.Unix(0, 0)}
	h := newErrorHandler(logger, time.Minute, clock.now)

	h.Handle(errors.New("traces export: context deadline exceeded"))
	clock.advance(20 * time.Second)
	h.Handle(errors.New("traces export: context deadline exceeded"))
	h.Handle(errors.New("metrics export: 401"))
	h.Handle(errors.New("metrics export: 401"))
	clock.advance(41 * time.Second)
	h.Handle(errors.New("traces export: context deadline exceeded"))

	lines := sink.lines(t)
	require.Len(t, lines, 3)
	assert.Equal(t, "opentelemetry sdk error", lines[0]["msg"])
	assert.Equal(t, "traces export: context deadline exceeded", lines[0]["error"])
	assert.NotContains(t, lines[0], "suppressed")
	assert.Equal(t, "metrics export: 401", lines[1]["error"])
	assert.Equal(t, "traces export: context deadline exceeded", lines[2]["error"])
	assert.EqualValues(t, 1, lines[2]["suppressed"])
}

func TestErrorHandler_BoundsDistinctErrors(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	clock := &fakeClock{t: time.Unix(0, 0)}
	h := newErrorHandler(logger, time.Minute, clock.now)

	for i := range maxThrottledErrors + 10 {
		h.Handle(fmt.Errorf("error %d", i))
	}
	assert.Len(t, sink.lines(t), maxThrottledErrors)
	assert.Len(t, h.entries, maxThrottledErrors)

	clock.advance(time.Minute)
	h.Handle(errors.New("a new error after the window"))
	assert.Len(t, sink.lines(t), maxThrottledErrors+1)
	assert.Len(t, h.entries, 1)
}

func TestRedactEndpoint(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://user:pass@collector.example:4318/v1/logs?token=x#f": "https://collector.example:4318/v1/logs",
		"http://collector:4318":            "http://collector:4318",
		"collector.internal:4317":          "collector.internal:4317",
		"user:pw@collector:4317?api_key=x": "collector:4317",
		"collector:4318/v1/logs?token=x":   "collector:4318/v1/logs",
		"":                                 "",
	}
	for in, want := range cases {
		assert.Equal(t, want, redactEndpoint(in), in)
	}
}

func TestOTLPExporter_LogsOnceWhenTheCollectorIsUnreachable(t *testing.T) {
	t.Parallel()
	logger, sink := newSinkLogger()
	s := Settings{
		Endpoint: "http://127.0.0.1:1",
		Protocol: ProtocolHTTP,
		Insecure: true,
		Timeout:  200 * time.Millisecond,
	}
	exp, err := newOTLPExporter(context.Background(), s, logger)
	require.NoError(t, err)
	exp.SetDataClass(metrics.Raw)

	require.NoError(t, exp.Publish(context.Background(), fullEvent()))
	exp.Close()

	var warned int
	for _, line := range sink.lines(t) {
		assert.NotEqual(t, "otlp exporter flush failed on close", line["msg"])
		if line["msg"] == msgExportFailed {
			warned++
			assert.Equal(t, "http://127.0.0.1:1", line["endpoint"])
			assert.Equal(t, "raw", line["class"])
		}
	}
	assert.Equal(t, 1, warned, "an unreachable collector must leave exactly one WARN line")
}
