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

package events_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvent_MarshalMCPBlock(t *testing.T) {
	evt := events.Event{
		SchemaVersion: events.SchemaVersion,
		Kind:          events.KindMCP,
		TraceID:       "trace-1",
		MCP: &events.MCP{
			Method:            "tools/call",
			Operation:         "tool",
			ServerName:        "asana",
			Host:              "mcp.asana.com",
			Tool:              "search",
			UpstreamStatus:    "ok",
			UpstreamLatencyMs: 120,
		},
	}

	raw, err := json.Marshal(evt)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	assert.Equal(t, "mcp", decoded["kind"])
	mcp, ok := decoded["mcp"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "tools/call", mcp["method"])
	assert.Equal(t, "asana", mcp["server_name"])
	assert.Equal(t, "mcp.asana.com", mcp["host"])
	assert.Equal(t, float64(120), mcp["upstream_latency_ms"])
}

func TestEvent_LLMOmitsMCP(t *testing.T) {
	evt := events.Event{
		SchemaVersion: events.SchemaVersion,
		Kind:          events.KindLLM,
		TraceID:       "trace-2",
	}

	raw, err := json.Marshal(evt)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))

	assert.Equal(t, "llm", decoded["kind"])
	_, hasMCP := decoded["mcp"]
	assert.False(t, hasMCP)
}
