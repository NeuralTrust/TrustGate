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

package usage_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

type captureEmitter struct {
	mu      sync.Mutex
	records []usagedomain.Record
}

func (c *captureEmitter) Emit(_ context.Context, r usagedomain.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r)
}

type outcomeCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *outcomeCounter) Outcome(outcome string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[string]int{}
	}
	c.counts[outcome] += n
}

var startTime = time.Date(2026, 10, 20, 10, 5, 25, 123456789, time.FixedZone("CEST", 2*3600))

func llmTrace(tenant string, tierApplied ...bool) *trace.RequestTrace {
	rt := trace.New("trace-llm", trace.Metadata{GatewayID: "gw-1", TenantID: tenant, ConsumerID: "cons-1", Kind: events.KindLLM})
	for _, applied := range tierApplied {
		span := rt.StartSpan(trace.SpanLLM, "llm")
		span.LLM.TierApplied = applied
	}
	return rt
}

func llmTraceWithOutcomes(outcomes ...string) *trace.RequestTrace {
	rt := trace.New("trace-llm", trace.Metadata{GatewayID: "gw-1", TenantID: "tenant-1", ConsumerID: "cons-1", Kind: events.KindLLM})
	for _, outcome := range outcomes {
		rt.StartSpan(trace.SpanLLM, "llm").LLM.Outcome = outcome
	}
	return rt
}

func mcpTrace(httpStatus, rpcCode int) *trace.RequestTrace {
	rt := trace.New("trace-mcp", trace.Metadata{GatewayID: "gw-1", TenantID: "tenant-1", Kind: events.KindMCP})
	rt.StartSpan(trace.SpanMCP, "mcp").SetMCPStatus(httpStatus, rpcCode)
	return rt
}

func TestRequestRecorder_Outcomes(t *testing.T) {
	t.Parallel()
	metaTool := mcpTrace(200, 0)
	metaTool.MarkMetaTool()
	tests := []struct {
		name         string
		rt           *trace.RequestTrace
		status       int
		wantRecord   bool
		wantSmart    int64
		wantSkipped  int
		wantTraceID  string
		wantConsumer string
	}{
		{name: "served", rt: llmTrace("tenant-1", false), status: 200, wantRecord: true, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "policy block", rt: llmTrace("tenant-1"), status: 403, wantRecord: true, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "client error", rt: llmTrace("tenant-1"), status: 400, wantRecord: true, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "unauthorized", rt: llmTrace("tenant-1"), status: 401},
		{name: "usage exhausted", rt: llmTrace("tenant-1"), status: 402},
		{name: "rate limited", rt: llmTrace("tenant-1"), status: 429},
		{name: "server error", rt: llmTrace("tenant-1", false), status: 500},
		{name: "upstream unavailable", rt: llmTrace("tenant-1", false), status: 503},
		{name: "upstream 429 recovered by a fallback", rt: llmTrace("tenant-1", false, false), status: 200, wantRecord: true, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "smart routing on the served attempt", rt: llmTrace("tenant-1", false, true), status: 200, wantRecord: true, wantSmart: 1, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "smart routing only on a failed attempt", rt: llmTrace("tenant-1", true, false), status: 200, wantRecord: true, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "provider refused the request", rt: llmTraceWithOutcomes("terminal"), status: 404},
		{name: "provider failed on every attempt", rt: llmTraceWithOutcomes("retryable", "retryable"), status: 400},
		{name: "provider failure recovered by a fallback", rt: llmTraceWithOutcomes("retryable", "success"), status: 200, wantRecord: true, wantTraceID: "trace-llm", wantConsumer: "cons-1"},
		{name: "no tenant", rt: llmTrace(""), status: 200, wantSkipped: 1},
		{name: "mcp served", rt: mcpTrace(200, 0), status: 200, wantRecord: true, wantTraceID: "trace-mcp"},
		{name: "mcp rate limited on http 200", rt: mcpTrace(200, int(appmcp.CodeRateLimited)), status: 200},
		{name: "mcp logical status wins", rt: mcpTrace(502, 0), status: 200},
		{name: "mcp policy block", rt: mcpTrace(403, -32001), status: 200, wantRecord: true, wantTraceID: "trace-mcp"},
		{name: "mcp meta-tool", rt: metaTool, status: 200},
		{name: "no trace", rt: nil, status: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			emitter := &captureEmitter{}
			outcomes := &outcomeCounter{}
			rec := appusage.NewRequestRecorder(true, emitter, outcomes)
			rec.Record(context.Background(), tt.rt, tt.status, startTime)

			assert.Equal(t, tt.wantSkipped, outcomes.counts[usagedomain.OutcomeSkipped])
			if !tt.wantRecord {
				assert.Empty(t, emitter.records)
				return
			}
			require.Len(t, emitter.records, 1)
			r := emitter.records[0]
			assert.Equal(t, "trustgate:"+tt.wantTraceID, r.EventID)
			assert.Equal(t, tt.wantTraceID, r.TraceID)
			assert.Equal(t, "tenant-1", r.TenantID)
			assert.Equal(t, "gw-1", r.GatewayID)
			assert.Equal(t, tt.wantConsumer, r.ConsumerID)
			assert.Equal(t, int64(1), r.Requests)
			assert.Equal(t, tt.wantSmart, r.SmartRoutingExecutions)
			assert.Zero(t, r.TopicClassificationChars)
			assert.Equal(t, time.Date(2026, 10, 20, 8, 5, 25, 123000000, time.UTC), r.OccurredOn)
		})
	}
}

func TestRequestRecorder_Disabled(t *testing.T) {
	t.Parallel()
	emitter := &captureEmitter{}
	rec := appusage.NewRequestRecorder(false, emitter, &outcomeCounter{})
	assert.False(t, rec.Enabled())
	rec.Record(context.Background(), llmTrace("tenant-1"), 200, startTime)
	assert.Empty(t, emitter.records)
	assert.False(t, appusage.NewRequestRecorder(true, nil, nil).Enabled())
}
