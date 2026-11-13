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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilder_A2AFoldsTheCall(t *testing.T) {
	rt := trace.New("trace-a2a", trace.Metadata{GatewayID: "gw-1", ConsumerID: "c-1", Kind: events.KindA2A})
	span := rt.StartSpan(trace.SpanA2A, "message/send")
	span.SetA2A(trace.A2AAttrs{
		Method:              "message/send",
		RegistryID:          "reg-1",
		AgentName:           "Travel planner",
		Provider:            "azure_foundry",
		ProtocolVersion:     "0.3",
		TaskID:              "t-1",
		ContextID:           "c-1",
		TaskState:           "working",
		UpstreamStatus:      http.StatusOK,
		Outcome:             "upstream_timeout",
		Reason:              "upstream_timeout",
		IdentityMode:        "delegation",
		IdentitySubjectKind: "user",
		RPCErrorCode:        -32092,
	})
	span.SetLatency(150 * time.Millisecond)

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/bot/agents/reg-1"}
	resp := &infracontext.ResponseContext{StatusCode: http.StatusOK}
	start := time.UnixMilli(2_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(200*time.Millisecond))

	assert.Equal(t, events.KindA2A, evt.Kind)
	assert.Nil(t, evt.MCP)
	assert.Equal(t, &events.A2A{
		Method:              "message/send",
		RegistryID:          "reg-1",
		AgentName:           "Travel planner",
		Provider:            "azure_foundry",
		ProtocolVersion:     "0.3",
		TaskID:              "t-1",
		ContextID:           "c-1",
		TaskState:           "working",
		UpstreamStatus:      http.StatusOK,
		Outcome:             "upstream_timeout",
		Reason:              "upstream_timeout",
		IdentityMode:        "delegation",
		IdentitySubjectKind: "user",
		RPCErrorCode:        -32092,
	}, evt.A2A)
	assert.True(t, evt.Status.IsTimeout)
	require.NotNil(t, evt.Latency.ProviderMs)
	assert.Equal(t, int64(150), *evt.Latency.ProviderMs)
	assert.Equal(t, int64(50), evt.Latency.GatewayMs)
	assert.Nil(t, evt.Usage)
}

// The Activity list names an A2A call by the text it sends, in either
// protocol version; a call with no message has no preview.
func TestBuilder_A2APreviewIsTheMessageText(t *testing.T) {
	cases := map[string]string{
		`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"ROLE_USER","messageId":"1","parts":[{"text":"Hello!"},{"data":{"a":1}},{"text":"Find flats"}]}}}`:                             "Hello! Find flats",
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","kind":"message","messageId":"1","parts":[{"kind":"text","text":"Book a trip"},{"kind":"file","file":{"uri":"x"}}]}}}`: "Book a trip",
		`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t-1"}}`: "",
		`{"model":"x","messages":[{"role":"user","content":"Hi"},{"role":"assistant","content":"Hello"},{"role":"user","content":[{"type":"text","text":"Flights?"}]}]}`: "Flights?",
	}
	for body, want := range cases {
		rt := trace.New("trace-a2a", trace.Metadata{GatewayID: "gw-1", Kind: events.KindA2A})
		req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/bot/agents/reg-1", Body: []byte(body)}
		start := time.UnixMilli(2_000_000)
		evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, &infracontext.ResponseContext{StatusCode: http.StatusOK}, start, start.Add(time.Millisecond))
		assert.Equal(t, want, evt.Request.Preview, body)
	}
}

// The tokens an agent reports are the event's usage, as an LLM call's are.
func TestBuilder_A2ATokensAreTheUsage(t *testing.T) {
	rt := trace.New("trace-a2a", trace.Metadata{GatewayID: "gw-1", Kind: events.KindA2A})
	span := rt.StartSpan(trace.SpanA2A, "message/send")
	span.SetA2A(trace.A2AAttrs{Method: "message/send", Provider: "agentcore_harness", InputTokens: 30, OutputTokens: 12})
	span.End()
	start := time.UnixMilli(2_000_000)
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt,
		&infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/bot/agents/reg-1"},
		&infracontext.ResponseContext{StatusCode: http.StatusOK}, start, start.Add(time.Millisecond))

	require.NotNil(t, evt.Usage)
	assert.Equal(t, events.Usage{PromptTokens: 30, CompletionTokens: 12, TotalTokens: 42}, *evt.Usage)
}

// LLM and MCP events carry no a2a block.
func TestBuilder_OtherKindsCarryNoA2A(t *testing.T) {
	for _, kind := range []string{events.KindLLM, events.KindMCP} {
		rt := trace.New("trace", trace.Metadata{GatewayID: "gw-1", Kind: kind})
		req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
		resp := &infracontext.ResponseContext{StatusCode: http.StatusOK}
		start := time.UnixMilli(2_000_000)
		evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, start, start.Add(time.Millisecond))
		raw, err := json.Marshal(evt)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), `"a2a"`, kind)
	}
}
