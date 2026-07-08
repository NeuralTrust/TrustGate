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
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mcpSpan(name string, attrs *trace.MCPAttrs, latency time.Duration) *trace.Span {
	span := &trace.Span{Type: trace.SpanMCP, Name: name, MCP: attrs}
	span.SetLatency(latency)
	return span
}

func TestBuilder_MCPFoldsUpstreamAndLatency(t *testing.T) {
	rt := trace.New("trace-mcp", trace.Metadata{
		GatewayID:    "gw-1",
		TenantID:       "team-9",
		ConsumerID:   "c-1",
		ConsumerName: "agent",
		Kind:         events.KindMCP,
	})
	_ = rt.AddSpan(mcpSpan("tools/call", &trace.MCPAttrs{
		Method:         "tools/call",
		Operation:      "tool",
		Tool:           "search",
		UpstreamTool:   "search",
		ServerName:     "asana",
		RegistryID:     "reg-7",
		Host:           "mcp.asana.com",
		CatalogCode:    "com.asana/mcp",
		Transport:      "streamable-http",
		UpstreamStatus: "ok",
	}, 120*time.Millisecond))

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/mcp", Body: []byte(`{"jsonrpc":"2.0"}`)}
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"result":{}}`)}
	start := time.UnixMilli(2_000_000)
	end := start.Add(200 * time.Millisecond)

	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, end)

	assert.Equal(t, events.KindMCP, evt.Kind)
	assert.Equal(t, "team-9", evt.TenantID)
	assert.Equal(t, "c-1", evt.Consumer.ID)
	require.NotNil(t, evt.MCP)
	assert.Equal(t, "tools/call", evt.MCP.Method)
	assert.Equal(t, "tool", evt.MCP.Operation)
	assert.Equal(t, "search", evt.MCP.Tool)
	assert.Equal(t, "mcp.asana.com", evt.MCP.Host)
	assert.Equal(t, "asana", evt.MCP.ServerName)
	assert.Equal(t, "com.asana/mcp", evt.MCP.CatalogCode)
	assert.Equal(t, "ok", evt.MCP.UpstreamStatus)
	assert.Equal(t, int64(120), evt.MCP.UpstreamLatencyMs)

	assert.Equal(t, int64(200), evt.Latency.TotalMs)
	assert.Equal(t, int64(120), evt.Latency.ProviderMs)
	assert.Equal(t, int64(80), evt.Latency.GatewayMs)

	assert.Nil(t, evt.Usage)
	assert.Nil(t, evt.Cost)
	assert.Empty(t, evt.Attempts)
	assert.Empty(t, evt.PolicyChain)
}

func TestBuilder_LLMKindDefault(t *testing.T) {
	rt := trace.New("trace-llm", trace.Metadata{GatewayID: "gw-1"})
	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	start := time.UnixMilli(1_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))

	assert.Equal(t, events.KindLLM, evt.Kind)
	assert.Nil(t, evt.MCP)
}
