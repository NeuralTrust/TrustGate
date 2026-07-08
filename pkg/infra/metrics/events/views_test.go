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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fullEvent() events.Event {
	respBody := "response output body"
	return events.Event{
		SchemaVersion: events.SchemaVersion,
		Kind:          events.KindLLM,
		TraceID:       "trace-1",
		GatewayID:     "gw-1",
		TenantID:        "team-1",
		Timestamp:     "2026-07-06T00:00:00Z",
		OccurredOn:    1751760000,
		EndTimestamp:  1751760001,
		Consumer:      events.Consumer{ID: "c-1", Name: "consumer"},
		SessionID:     "sess-1",
		TurnID:        "turn-1",
		IP:            "203.0.113.7",
		Status:        events.Status{Code: 200, Outcome: "ok"},
		Security:      []string{"rule-a"},
		Request: events.Request{
			Method:   "POST",
			Path:     "/v1/chat",
			Provider: "openai",
			Model:    "gpt-4",
			Body:     "request input body",
			Headers:  map[string][]string{"X-Trace": {"abc"}},
		},
		Response: events.Response{
			StatusCode: 200,
			LatencyMs:  120,
			Body:       &respBody,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
		},
		Usage:       &events.Usage{PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30},
		Cost:        &events.Cost{Currency: "USD"},
		Latency:     events.Latency{TotalMs: 120},
		Attempts:    []events.Attempt{{Attempt: 1, Provider: "openai"}},
		PolicyChain: []events.PolicyEntry{{Name: "guard", Decision: "allow"}},
		MCP:         &events.MCP{Method: "tools/call", Prompt: "mcp prompt"},
	}
}

func TestEvent_MetadataView_ExcludesBodies(t *testing.T) {
	evt := fullEvent()

	meta := evt.MetadataView()

	assert.Empty(t, meta.Request.Body)
	assert.Nil(t, meta.Response.Body)

	assert.Equal(t, evt.SchemaVersion, meta.SchemaVersion)
	assert.Equal(t, evt.Kind, meta.Kind)
	assert.Equal(t, evt.TraceID, meta.TraceID)
	assert.Equal(t, evt.GatewayID, meta.GatewayID)
	assert.Equal(t, evt.TenantID, meta.TenantID)
	assert.Equal(t, evt.IP, meta.IP)
	assert.Equal(t, evt.Consumer, meta.Consumer)
	assert.Equal(t, evt.Status, meta.Status)
	assert.Equal(t, evt.Usage, meta.Usage)
	assert.Equal(t, evt.Cost, meta.Cost)
	assert.Equal(t, evt.Attempts, meta.Attempts)
	assert.Equal(t, evt.PolicyChain, meta.PolicyChain)
	assert.Equal(t, evt.MCP, meta.MCP)
	assert.Equal(t, evt.Request.Headers, meta.Request.Headers)
	assert.Equal(t, evt.Response.Headers, meta.Response.Headers)
	assert.Equal(t, evt.Request.Method, meta.Request.Method)
	assert.Equal(t, evt.Response.StatusCode, meta.Response.StatusCode)
}

func TestEvent_SensibleView_OnlyBodiesAndCorrelationKeys(t *testing.T) {
	evt := fullEvent()

	sensible := evt.SensibleView()

	assert.Equal(t, evt.Request.Body, sensible.Request.Body)
	require.NotNil(t, sensible.Response.Body)
	assert.Equal(t, *evt.Response.Body, *sensible.Response.Body)

	assert.Equal(t, evt.SchemaVersion, sensible.SchemaVersion)
	assert.Equal(t, evt.TraceID, sensible.TraceID)
	assert.Equal(t, evt.GatewayID, sensible.GatewayID)
	assert.Equal(t, evt.TenantID, sensible.TenantID)
	assert.Equal(t, evt.OccurredOn, sensible.OccurredOn)

	assert.Empty(t, sensible.Kind)
	assert.Empty(t, sensible.IP)
	assert.Equal(t, events.Consumer{}, sensible.Consumer)
	assert.Equal(t, events.Status{}, sensible.Status)
	assert.Nil(t, sensible.Usage)
	assert.Nil(t, sensible.Cost)
	assert.Nil(t, sensible.Attempts)
	assert.Nil(t, sensible.PolicyChain)
	assert.Nil(t, sensible.MCP)
	assert.Nil(t, sensible.Request.Headers)
	assert.Empty(t, sensible.Request.Method)
	assert.Nil(t, sensible.Response.Headers)
	assert.Zero(t, sensible.Response.StatusCode)
}

func TestEvent_Views_DoNotMutateOriginal(t *testing.T) {
	evt := fullEvent()
	originalReqBody := evt.Request.Body
	originalRespBody := *evt.Response.Body

	_ = evt.MetadataView()
	_ = evt.SensibleView()

	assert.Equal(t, originalReqBody, evt.Request.Body)
	require.NotNil(t, evt.Response.Body)
	assert.Equal(t, originalRespBody, *evt.Response.Body)
}
