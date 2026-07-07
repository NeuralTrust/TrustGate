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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
)

func TestEventToRecord_MCPAttributes(t *testing.T) {
	t.Parallel()
	evt := &events.Event{
		SchemaVersion: events.SchemaVersion,
		Kind:          events.KindMCP,
		TraceID:       "trace-mcp",
		GatewayID:     "gw-1",
		TeamID:        "team-1",
		Consumer:      events.Consumer{ID: "c-1", Name: "agent"},
		Status:        events.Status{Code: 200},
		Request:       events.Request{Method: "POST", Path: "/mcp"},
		Response:      events.Response{StatusCode: 200},
		Latency:       events.Latency{TotalMs: 200, ProviderMs: 120, GatewayMs: 80},
		MCP: &events.MCP{
			Method:            "tools/call",
			Operation:         "tool",
			ServerName:        "asana",
			RegistryID:        "reg-7",
			Host:              "mcp.asana.com",
			CatalogCode:       "com.asana/mcp",
			Transport:         "streamable-http",
			Tool:              "search",
			UpstreamTool:      "search",
			Targets:           3,
			UpstreamStatus:    "ok",
			UpstreamLatencyMs: 120,
		},
	}

	rec := eventToRecord(evt, metrics.Metadata, 4096)
	attrs := attrsOf(rec)

	assert.Equal(t, events.KindMCP, attrs[attrKind].AsString())
	assert.Equal(t, "tools/call", attrs[attrMCPMethod].AsString())
	assert.Equal(t, "tool", attrs[attrMCPOperation].AsString())
	assert.Equal(t, "asana", attrs[attrMCPServerName].AsString())
	assert.Equal(t, "mcp.asana.com", attrs[attrMCPHost].AsString())
	assert.Equal(t, "com.asana/mcp", attrs[attrMCPCatalogCode].AsString())
	assert.Equal(t, "streamable-http", attrs[attrMCPTransport].AsString())
	assert.Equal(t, "search", attrs[attrMCPTool].AsString())
	assert.Equal(t, "ok", attrs[attrMCPUpstreamStatus].AsString())
	assert.Equal(t, int64(3), attrs[attrMCPTargets].AsInt64())
	assert.Equal(t, int64(120), attrs[attrMCPUpstreamLatencyMs].AsInt64())
}

func TestEventToRecord_LLMKindNoMCP(t *testing.T) {
	t.Parallel()
	evt := fullEvent()
	evt.Kind = events.KindLLM

	rec := eventToRecord(evt, metrics.Metadata, 4096)
	attrs := attrsOf(rec)

	assert.Equal(t, events.KindLLM, attrs[attrKind].AsString())
	_, hasMethod := attrs[attrMCPMethod]
	assert.False(t, hasMethod)
}
