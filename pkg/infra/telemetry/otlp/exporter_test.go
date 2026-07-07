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
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (m *memExporter) Export(_ context.Context, records []sdklog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range records {
		m.records = append(m.records, r.Clone())
	}
	return nil
}

func (m *memExporter) Shutdown(context.Context) error   { return nil }
func (m *memExporter) ForceFlush(context.Context) error { return nil }

func (m *memExporter) all() []sdklog.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sdklog.Record, len(m.records))
	copy(out, m.records)
	return out
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func recordAttr(rec sdklog.Record, key string) (otellog.Value, bool) {
	var (
		value otellog.Value
		found bool
	)
	rec.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == key {
			value, found = kv.Value, true
			return false
		}
		return true
	})
	return value, found
}

func TestExporter_PublishEmitsOneRecord(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), time.Second)
	defer exp.Close()

	assert.Equal(t, ExporterName, exp.Name())
	require.NoError(t, exp.Publish(context.Background(), fullEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	assert.Equal(t, eventName, records[0].EventName())
	assert.Equal(t, otellog.SeverityInfo, records[0].Severity())

	trace, ok := recordAttr(records[0], attrTraceID)
	require.True(t, ok)
	assert.Equal(t, "trace-123", trace.AsString())
}

func TestExporter_PublishNeverEmitsBodies(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), time.Second)
	defer exp.Close()

	require.NoError(t, exp.Publish(context.Background(), fullEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	assert.Empty(t, records[0].Body().AsString())
	_, hasRequestBody := recordAttr(records[0], "trustgate.request.body")
	assert.False(t, hasRequestBody)
}

func TestExporter_DataClassDefaultsToMetadata(t *testing.T) {
	t.Parallel()
	exp := newExporterWithProvider(sdklog.NewLoggerProvider(), testLogger(), time.Second)
	defer exp.Close()
	assert.Equal(t, metrics.Metadata, exp.DataClass())
}

func TestExporter_RawClassEmitsBodies(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), time.Second)
	defer exp.Close()

	exp.SetDataClass(metrics.Raw)
	assert.Equal(t, metrics.Raw, exp.DataClass())
	require.NoError(t, exp.Publish(context.Background(), fullEvent()))

	records := mem.all()
	require.Len(t, records, 1)
	assert.Equal(t, rawEventName, records[0].EventName())

	reqBody, ok := recordAttr(records[0], attrRequestBody)
	require.True(t, ok)
	assert.Equal(t, "request-body", reqBody.AsString())
	respBody, ok := recordAttr(records[0], attrResponseBody)
	require.True(t, ok)
	assert.Equal(t, "hello world", respBody.AsString())

	trace, ok := recordAttr(records[0], attrTraceID)
	require.True(t, ok)
	assert.Equal(t, "trace-123", trace.AsString())

	_, hasMethod := recordAttr(records[0], "http.request.method")
	assert.False(t, hasMethod, "raw record must not carry sanitized metadata attributes")
}

func TestExporter_NilEventIsNoOp(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), time.Second)
	defer exp.Close()

	require.NoError(t, exp.Publish(context.Background(), nil))
	assert.Empty(t, mem.all())
}

func TestExporter_CloseFlushesBufferedRecords(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), 2*time.Second)

	require.NoError(t, exp.Publish(context.Background(), fullEvent()))
	exp.Close()

	assert.NotEmpty(t, mem.all())
}

func TestExporter_PublishAfterCloseErrors(t *testing.T) {
	t.Parallel()
	mem := &memExporter{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(mem)))
	exp := newExporterWithProvider(provider, testLogger(), time.Second)

	exp.Close()
	err := exp.Publish(context.Background(), fullEvent())
	assert.ErrorIs(t, err, errExporterClosed)
}

func TestNewLoggerProvider_BuildsForBothProtocols(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    Settings
	}{
		{
			name: "grpc insecure",
			s: Settings{
				Endpoint: "localhost:4317", Protocol: ProtocolGRPC, Signal: SignalLogs,
				Timeout: 5 * time.Second, Compression: compressionGzip, Insecure: true, MaxBodyBytes: 4096,
			},
		},
		{
			name: "http insecure no compression",
			s: Settings{
				Endpoint: "localhost:4318", Protocol: ProtocolHTTP, Signal: SignalLogs,
				Timeout: 5 * time.Second, Compression: compressionNone, Insecure: true, MaxBodyBytes: 4096,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			provider, err := newLoggerProvider(context.Background(), tc.s)
			require.NoError(t, err)
			require.NotNil(t, provider)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = provider.Shutdown(ctx)
		})
	}
}

func TestNewLoggerProvider_TLSFileError(t *testing.T) {
	t.Parallel()
	s := Settings{
		Endpoint: "localhost:4317", Protocol: ProtocolGRPC, Signal: SignalLogs,
		Timeout: 5 * time.Second, Compression: compressionGzip, MaxBodyBytes: 4096,
		TLS: &TLSSettings{CAFile: "/does/not/exist/ca.pem"},
	}
	_, err := newLoggerProvider(context.Background(), s)
	require.Error(t, err)
}
