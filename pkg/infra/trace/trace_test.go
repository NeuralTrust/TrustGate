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

package trace_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_GeneratesTraceIDWhenEmpty(t *testing.T) {
	rt := trace.New("", trace.Metadata{GatewayID: "gw"})
	assert.NotEmpty(t, rt.TraceID())
	assert.Equal(t, "gw", rt.Metadata().GatewayID)
}

func TestNew_KeepsProvidedTraceID(t *testing.T) {
	rt := trace.New("trace-123", trace.Metadata{})
	assert.Equal(t, "trace-123", rt.TraceID())
}

func TestSetConsumer_StampsMetadata(t *testing.T) {
	rt := trace.New("t", trace.Metadata{GatewayID: "gw"})
	rt.SetConsumer("consumer-1", "support-bot-eu")
	meta := rt.Metadata()
	assert.Equal(t, "consumer-1", meta.ConsumerID)
	assert.Equal(t, "support-bot-eu", meta.ConsumerName)
	assert.Equal(t, "gw", meta.GatewayID)
}

func TestStartSpan_RecordsTypedSpansInOrder(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	llm := rt.StartSpan(trace.SpanLLM, "openai")
	mcp := rt.StartSpan(trace.SpanMCP, "tool")

	spans := rt.Spans()
	require.Len(t, spans, 2)
	assert.Same(t, llm, spans[0])
	assert.Same(t, mcp, spans[1])
	assert.Equal(t, trace.SpanLLM, spans[0].Type)
	assert.Equal(t, trace.SpanMCP, spans[1].Type)
	assert.NotEmpty(t, spans[0].ID)
	assert.NotEqual(t, spans[0].ID, spans[1].ID)
}

func TestLLMUsage_ReturnsSpanUsageNotSum(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	first := rt.StartSpan(trace.SpanLLM, "openai")
	first.ObserveUsage(&adapter.CanonicalUsage{InputTokens: 5, OutputTokens: 5, TotalTokens: 10})
	first.End()

	served := rt.StartSpan(trace.SpanLLM, "openai")
	served.ObserveUsage(&adapter.CanonicalUsage{InputTokens: 7, OutputTokens: 3, TotalTokens: 10})
	served.End()

	usage := rt.LLMUsage()
	require.NotNil(t, usage)
	assert.Equal(t, 10, usage.TotalTokens, "must return the served span usage, not 20")
	assert.Equal(t, 7, usage.InputTokens)
}

func TestObserveLLMUsage_TargetsMostRecentLLMSpan(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	rt.StartSpan(trace.SpanLLM, "openai").End()
	_ = rt.StartSpan(trace.SpanLLM, "openai")

	rt.ObserveLLMUsage(&adapter.CanonicalUsage{InputTokens: 3, OutputTokens: 4, TotalTokens: 7})

	usage := rt.LLMUsage()
	require.NotNil(t, usage)
	assert.Equal(t, 7, usage.TotalTokens)
	assert.Nil(t, rt.Spans()[0].Usage())
	assert.NotNil(t, rt.Spans()[1].Usage())
}

func TestObserveLLMResult_TargetsMostRecentLLMSpanAndAccumulates(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	rt.StartSpan(trace.SpanLLM, "openai").End()
	_ = rt.StartSpan(trace.SpanLLM, "openai")

	rt.ObserveLLMResult("gpt-4o-2024-08-06", "")
	rt.ObserveLLMResult("", "stop")

	served, ok := rt.Spans()[1].LLMAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "gpt-4o-2024-08-06", served.Model)
	assert.Equal(t, "stop", served.FinishReason)

	first, ok := rt.Spans()[0].LLMAttrsCopy()
	require.True(t, ok)
	assert.Empty(t, first.Model)
	assert.Empty(t, first.FinishReason)
}

func TestObserveLLMResult_NoopWithoutLLMSpanOrEmpty(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	_ = rt.StartSpan(trace.SpanMCP, "tool")
	rt.ObserveLLMResult("gpt-4o", "stop")
	rt.ObserveLLMResult("", "")
	_, ok := rt.Spans()[0].LLMAttrsCopy()
	assert.False(t, ok)
}

func TestSpan_SetLLMResultIgnoresEmptyValues(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanLLM, "openai")
	span.SetLLMResult("claude-3-5-sonnet", "tool_calls")
	span.SetLLMResult("", "")
	attrs, ok := span.LLMAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "claude-3-5-sonnet", attrs.Model)
	assert.Equal(t, "tool_calls", attrs.FinishReason)
}

func TestSpan_SetScore(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, "prompt_guard")
	span.SetScore(0.93, "prompt-injection")
	attrs := span.PluginAttrsCopy()
	require.NotNil(t, attrs.Score)
	assert.InDelta(t, 0.93, *attrs.Score, 1e-9)
	assert.Equal(t, "prompt-injection", attrs.ScoreLabel)
}

func TestObserveLLMUsage_NoopWithoutLLMSpanOrNil(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	_ = rt.StartSpan(trace.SpanMCP, "tool")
	rt.ObserveLLMUsage(&adapter.CanonicalUsage{TotalTokens: 9})
	rt.ObserveLLMUsage(nil)
	assert.Nil(t, rt.LLMUsage())
}

func TestLLMUsage_NilWithoutLLMSpan(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	mcp := rt.StartSpan(trace.SpanMCP, "tool")
	mcp.End()
	assert.Nil(t, rt.LLMUsage(), "MCP-only request has no token usage")
}

func TestSpan_ObserveUsageLatestWins(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanLLM, "anthropic")
	span.ObserveUsage(&adapter.CanonicalUsage{OutputTokens: 1, TotalTokens: 1})
	span.ObserveUsage(&adapter.CanonicalUsage{OutputTokens: 4, TotalTokens: 4})
	span.ObserveUsage(nil)
	require.NotNil(t, span.Usage())
	assert.Equal(t, 4, span.Usage().TotalTokens)
}

func TestSpan_LatencyZeroUntilEnded(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanLLM, "openai")
	assert.Zero(t, span.Latency())
	span.End()
	assert.GreaterOrEqual(t, span.Latency().Nanoseconds(), int64(0))
	assert.False(t, span.EndedAt().IsZero())
}

func TestDone_FiresOnCompleteOnlyAfterAsyncWorkFinishes(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	var fired int32
	rt.OnComplete(func() { atomic.AddInt32(&fired, 1) })

	rt.AddAsync() // post_response registered before the request hold is released

	rt.Done() // request hold released, but async still pending
	assert.Equal(t, int32(0), atomic.LoadInt32(&fired), "must not fire while async work is pending")

	rt.Done() // async finished
	assert.Equal(t, int32(1), atomic.LoadInt32(&fired), "fires once both request and async are done")
}

func TestDone_FiresOnceWithoutAsyncWork(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	var fired int32
	rt.OnComplete(func() { atomic.AddInt32(&fired, 1) })

	rt.Done()
	rt.Done() // extra Done must not double-fire
	assert.Equal(t, int32(1), atomic.LoadInt32(&fired))
}

func TestContext_RoundTrip(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	assert.Same(t, rt, trace.FromContext(ctx))
}

func TestFromContext_NilSafe(t *testing.T) {
	var nilCtx context.Context
	assert.Nil(t, trace.FromContext(nilCtx))
	assert.Nil(t, trace.FromContext(context.Background()))
}

func TestRequestTrace_ConcurrentSpanRecording(t *testing.T) {
	rt := trace.New("t", trace.Metadata{})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := rt.StartSpan(trace.SpanLLM, "openai")
			s.ObserveUsage(&adapter.CanonicalUsage{TotalTokens: 1})
			s.End()
		}()
	}
	wg.Wait()
	assert.Len(t, rt.Spans(), 50)
}
