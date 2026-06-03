package metrics_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	apptelemetry "github.com/NeuralTrust/AgentGateway/pkg/app/telemetry"
	apptelemetrymocks "github.com/NeuralTrust/AgentGateway/pkg/app/telemetry/mocks"
	domaintelemetry "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWorker_HasDefaultExporters(t *testing.T) {
	builder := apptelemetrymocks.NewExportersBuilder(t)

	with := appmetrics.NewWorker(newTestLogger(), builder, []apptelemetry.Exporter{
		apptelemetrymocks.NewExporter(t),
	})
	assert.True(t, with.HasDefaultExporters())

	without := appmetrics.NewWorker(newTestLogger(), builder, nil)
	assert.False(t, without.HasDefaultExporters())
}

func TestWorker_ProcessFeedsDefaultExporter(t *testing.T) {
	builder := apptelemetrymocks.NewExportersBuilder(t)
	exporter := apptelemetrymocks.NewExporter(t)
	exporter.EXPECT().Name().Return("kafka").Maybe()
	exporter.EXPECT().Close().Return().Maybe()

	handled := make(chan metric_events.Event, 1)
	exporter.EXPECT().
		Handle(mock.Anything, mock.Anything).
		Run(func(_ context.Context, evt metric_events.Event) { handled <- evt }).
		Return(nil).
		Once()

	w := appmetrics.NewWorker(newTestLogger(), builder, []apptelemetry.Exporter{exporter})
	w.StartWorkers(1)
	defer w.Shutdown()

	start := time.Now()
	req := &infracontext.RequestContext{
		GatewayID: "gw-1",
		Method:    "POST",
		Path:      "/v1/chat/completions",
		IP:        "10.0.0.1",
		Headers:   map[string][]string{"X-Conversation-Id": {"conv-1"}},
		Body:      []byte(`{"model":"gpt"}`),
	}
	resp := &infracontext.ResponseContext{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ok":true}`),
	}

	w.Process(nil, nil, req, resp, start, start.Add(25*time.Millisecond))

	select {
	case evt := <-handled:
		assert.Equal(t, "POST", evt.Method)
		assert.Equal(t, "/v1/chat/completions", evt.Path)
		assert.Equal(t, "gw-1", evt.GatewayID)
		assert.Equal(t, 200, evt.StatusCode)
		assert.Equal(t, "conv-1", evt.ConversationID)
		assert.Equal(t, int64(25), evt.Latency)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for exporter to handle event")
	}
}

func TestWorker_ProcessBuildsEventsFromTraceSpans(t *testing.T) {
	builder := apptelemetrymocks.NewExportersBuilder(t)
	exporter := apptelemetrymocks.NewExporter(t)
	exporter.EXPECT().Name().Return("kafka").Maybe()
	exporter.EXPECT().Close().Return().Maybe()

	handled := make(chan metric_events.Event, 1)
	exporter.EXPECT().
		Handle(mock.Anything, mock.Anything).
		Run(func(_ context.Context, evt metric_events.Event) { handled <- evt }).
		Return(nil).
		Once()

	w := appmetrics.NewWorker(newTestLogger(), builder, []apptelemetry.Exporter{exporter})
	w.StartWorkers(1)
	defer w.Shutdown()

	req := &infracontext.RequestContext{
		GatewayID: "gw-1",
		Method:    "POST",
		Path:      "/v1/chat/completions",
	}
	resp := &infracontext.ResponseContext{
		StatusCode: 200,
		Streaming:  true,
		Body:       []byte("data: chunk\n"),
	}

	rt := trace.New("trace-1", trace.Metadata{GatewayID: "gw-1"})
	span := rt.StartSpan(trace.SpanLLM, "openai")
	span.LLM.RegistryID = "backend-9"
	span.SetStatusCode(200)
	span.ObserveUsage(&adapter.CanonicalUsage{InputTokens: 11, OutputTokens: 22, TotalTokens: 33})
	span.End()

	w.Process(nil, rt, req, resp, time.Now(), time.Now())

	select {
	case evt := <-handled:
		assert.True(t, evt.Streaming, "streaming flag must reach the event")
		assert.Equal(t, "trace-1", evt.TraceID, "event correlates with the trace id")
		assert.Equal(t, "backend-9", evt.RegistryID, "span backend mapped onto the event")
		require.NotNil(t, evt.Usage, "usage must come from the LLM span")
		assert.Equal(t, 11, evt.Usage.InputTokens)
		assert.Equal(t, 22, evt.Usage.OutputTokens)
		assert.Equal(t, 33, evt.Usage.TotalTokens)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for exporter to handle event")
	}
}

func TestWorker_ProcessExporterFailureDoesNotPanic(t *testing.T) {
	builder := apptelemetrymocks.NewExportersBuilder(t)
	exporter := apptelemetrymocks.NewExporter(t)
	exporter.EXPECT().Name().Return("kafka").Maybe()
	exporter.EXPECT().Close().Return().Maybe()

	done := make(chan struct{}, 1)
	exporter.EXPECT().
		Handle(mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ metric_events.Event) { done <- struct{}{} }).
		Return(errors.New("delivery failed")).
		Once()

	w := appmetrics.NewWorker(newTestLogger(), builder, []apptelemetry.Exporter{exporter})
	w.StartWorkers(1)
	defer w.Shutdown()

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "GET", Path: "/v1/x"}
	resp := &infracontext.ResponseContext{StatusCode: 502}
	w.Process(nil, nil, req, resp, time.Now(), time.Now())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for exporter handle")
	}
}

func TestWorker_ProcessCachesBuiltExporters(t *testing.T) {
	exporter := apptelemetrymocks.NewExporter(t)
	exporter.EXPECT().Name().Return("kafka").Maybe()
	exporter.EXPECT().Close().Return().Maybe()

	handled := make(chan struct{}, 2)
	exporter.EXPECT().
		Handle(mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ metric_events.Event) { handled <- struct{}{} }).
		Return(nil)

	builder := apptelemetrymocks.NewExportersBuilder(t)
	builder.EXPECT().
		Build(mock.Anything).
		Return([]apptelemetry.Exporter{exporter}, nil).
		Once() // must build only once across both calls thanks to the cache

	w := appmetrics.NewWorker(newTestLogger(), builder, nil)
	w.StartWorkers(1)
	defer w.Shutdown()

	exporters := []domaintelemetry.ExporterConfig{{Name: "kafka", Settings: map[string]interface{}{"topic": "t"}}}
	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "GET", Path: "/v1/x"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	for range 2 {
		w.Process(exporters, nil, req, resp, time.Now(), time.Now())
		select {
		case <-handled:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for exporter handle")
		}
	}
}

func TestWorker_ProcessNilArgsIsNoop(t *testing.T) {
	builder := apptelemetrymocks.NewExportersBuilder(t)
	w := appmetrics.NewWorker(newTestLogger(), builder, nil)
	w.StartWorkers(1)
	defer w.Shutdown()

	req := &infracontext.RequestContext{GatewayID: "gw-1"}
	resp := &infracontext.ResponseContext{}
	// Nil trace / req / resp must not panic.
	w.Process(nil, nil, req, resp, time.Now(), time.Now())
	w.Process(nil, nil, nil, resp, time.Now(), time.Now())
	w.Process(nil, nil, req, nil, time.Now(), time.Now())
	time.Sleep(20 * time.Millisecond)
}

func TestWorker_ProcessNoExportersIsNoop(t *testing.T) {
	builder := apptelemetrymocks.NewExportersBuilder(t)
	w := appmetrics.NewWorker(newTestLogger(), builder, nil)
	w.StartWorkers(1)
	defer w.Shutdown()

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "GET", Path: "/v1/x"}
	resp := &infracontext.ResponseContext{StatusCode: 200}
	// No default exporters and no explicit exporters: must not block or panic.
	w.Process(nil, nil, req, resp, time.Now(), time.Now())

	// Give the worker goroutine a moment; nothing should happen.
	time.Sleep(50 * time.Millisecond)
	require.True(t, true)
}
