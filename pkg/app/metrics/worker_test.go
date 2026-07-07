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

package metrics_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type captureExporter struct {
	mu     sync.Mutex
	events []*events.Event
}

func (c *captureExporter) Name() string { return "capture" }

func (c *captureExporter) DataClass() metrics.DataClass { return metrics.Metadata }

func (c *captureExporter) Publish(_ context.Context, evt *events.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evt)
	return nil
}

func (c *captureExporter) Close() {}

func (c *captureExporter) snapshot() []*events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*events.Event(nil), c.events...)
}

type stubPricingResolver struct {
	price appcatalog.Pricing
}

func (s stubPricingResolver) Resolve(_ context.Context, _ string, _ string) appcatalog.Pricing {
	return s.price
}

// TestWorker_PublishesConsolidatedEvent exercises the full path: Process ->
// pipeline -> builder -> exporter, asserting that a single consolidated event
// with the expected shape reaches the exporter.
func TestWorker_PublishesConsolidatedEvent(t *testing.T) {
	capture := &captureExporter{}
	builder := appmetrics.NewBuilder(adapter.NewRegistry(), stubPricingResolver{
		price: appcatalog.Pricing{ModelLabel: "GPT-4o", InputPrice: 0.0000025, OutputPrice: 0.00001, Found: true},
	})
	pipeline := appmetrics.NewPipeline(builder, nil, nil, newTestLogger(), capture)

	w := appmetrics.NewWorker(newTestLogger(), pipeline)
	w.StartWorkers(1)
	defer w.Shutdown()

	rt := trace.New("trace-fn", trace.Metadata{GatewayID: "gw-1", ConsumerName: "support-bot"})
	llm := &trace.Span{Type: trace.SpanLLM, Name: "openai", LLM: &trace.LLMAttrs{
		Provider:     "openai",
		RegistryID:   "reg-1",
		Model:        "gpt-4o-2024-08-06",
		FinishReason: "stop",
		Attempt:      1,
		Outcome:      "success",
		Usage:        &adapter.CanonicalUsage{InputTokens: 10, OutputTokens: 20, TotalTokens: 30},
	}}
	llm.SetStatusCode(200)
	llm.SetLatency(300 * time.Millisecond)
	_ = rt.AddSpan(llm)

	req := &infracontext.RequestContext{
		GatewayID:    "gw-1",
		Method:       "POST",
		Path:         "/v1/chat/completions",
		Body:         []byte(`{"model":"gpt-4o","temperature":0.5,"max_tokens":64,"stream":false,"messages":[{"role":"user","content":"hi"}]}`),
		SourceFormat: string(adapter.FormatOpenAI),
	}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x"}`)}

	start := time.UnixMilli(5_000_000)
	end := start.Add(310 * time.Millisecond)

	w.Process(rt, req, resp, start, end, nil)

	require.Eventually(t, func() bool {
		return len(capture.snapshot()) == 1
	}, time.Second, 10*time.Millisecond)

	evt := capture.snapshot()[0]
	assert.Equal(t, events.SchemaVersion, evt.SchemaVersion)
	assert.Equal(t, "trace-fn", evt.TraceID)
	assert.Equal(t, "gw-1", evt.GatewayID)
	assert.Equal(t, "support-bot", evt.Consumer.Name)
	assert.Equal(t, "openai", evt.Request.Provider)
	assert.Equal(t, "gpt-4o-2024-08-06", evt.Request.Model)
	assert.Equal(t, "stop", evt.Response.FinishReason)
	require.NotNil(t, evt.Usage)
	assert.Equal(t, 30, evt.Usage.TotalTokens)
	require.NotNil(t, evt.Cost)
	assert.Equal(t, "USD", evt.Cost.Currency)
	require.Len(t, evt.Attempts, 1)
}

// TestWorker_NilPipelineAndNilArgsAreNoop guards the no-op paths: a worker with
// no pipeline (telemetry disabled) and Process called with nil req/resp must
// never panic.
func TestWorker_NilPipelineAndNilArgsAreNoop(t *testing.T) {
	w := appmetrics.NewWorker(newTestLogger(), nil)
	w.StartWorkers(1)
	defer w.Shutdown()

	req := &infracontext.RequestContext{GatewayID: "gw-1"}
	resp := &infracontext.ResponseContext{}
	w.Process(nil, req, resp, time.Now(), time.Now(), nil)
	w.Process(nil, nil, resp, time.Now(), time.Now(), nil)
	w.Process(nil, req, nil, time.Now(), time.Now(), nil)
	time.Sleep(20 * time.Millisecond)
}
