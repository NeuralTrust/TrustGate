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

package a2a_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	harnessARN  = "arn:aws:bedrock-agentcore:us-east-1:888577023128:harness/harness_0m4lj-8nAuuzxT1b"
	builtCard   = `{"name":"agent","capabilities":{"streaming":false}}`
	sendHello   = `{"message":{"kind":"message","messageId":"m-1","role":"user","parts":[{"kind":"text","text":"Hello!"},{"kind":"data","data":{"city":"Paris"}}]}}`
	harnessBase = "https://bedrock-agentcore.us-east-1.amazonaws.com/harnesses/invoke?harnessArn=arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A888577023128%3Aharness%2Fharness_0m4lj-8nAuuzxT1b&qualifier=DEFAULT"
)

func harnessTarget() *registrydomain.A2ATarget {
	return &registrydomain.A2ATarget{
		Provider:         registrydomain.A2AProviderAgentCoreHarness,
		AgentCoreHarness: &registrydomain.HarnessLocator{HarnessARN: harnessARN},
		Auth:             &registrydomain.MCPAuth{Mode: registrydomain.A2AAuthModeCloud},
		CloudAuth:        &registrydomain.A2ACloudAuth{AWS: &registrydomain.A2AAWSAuth{}},
	}
}

type harnessEvent struct {
	kind    string // event, exception
	name    string
	payload string
}

// eventStream answers with InvokeHarness's AWS event stream.
func eventStream(t *testing.T, events ...harnessEvent) http.HandlerFunc {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	for _, e := range events {
		var h eventstream.Headers
		h.Set(":message-type", eventstream.StringValue(e.kind))
		if e.kind == "exception" {
			h.Set(":exception-type", eventstream.StringValue(e.name))
		} else {
			h.Set(":event-type", eventstream.StringValue(e.name))
		}
		require.NoError(t, enc.Encode(&buf, eventstream.Message{Headers: h, Payload: []byte(e.payload)}))
	}
	body := buf.Bytes()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		_, _ = w.Write(body)
	}
}

func answerText(t *testing.T, result json.RawMessage) (text, contextID string) {
	t.Helper()
	var msg struct {
		Kind      string `json:"kind"`
		Role      string `json:"role"`
		ContextID string `json:"contextId"`
		Parts     []struct {
			Kind string `json:"kind"`
			Text string `json:"text"`
		} `json:"parts"`
	}
	require.NoError(t, json.Unmarshal(result, &msg))
	require.Equal(t, "message", msg.Kind)
	require.Equal(t, "agent", msg.Role)
	require.Len(t, msg.Parts, 1)
	return msg.Parts[0].Text, msg.ContextID
}

func TestHarnessSendsTheMessageAndReadsTheEventStream(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, eventStream(t,
		harnessEvent{"event", "messageStart", `{"role":"assistant"}`},
		harnessEvent{"event", "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"It is "}}`},
		harnessEvent{"event", "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"sunny."}}`},
		harnessEvent{"event", "contentBlockStop", `{"contentBlockIndex":0}`},
		harnessEvent{"event", "messageStop", `{"stopReason":"end_turn"}`},
		harnessEvent{"event", "metadata", `{"usage":{"inputTokens":3,"outputTokens":4,"totalTokens":7}}`},
	))
	h := newHostedHarness(t, ag, a2a.Version03, harnessTarget(), builtCard)

	result, rpcErr := h.send(t, rpcRequest("message/send", sendHello), nil)
	require.Nil(t, rpcErr)
	text, contextID := answerText(t, result)
	assert.Equal(t, "It is sunny.", text)
	require.NotEmpty(t, contextID)

	assert.Equal(t, []string{"POST " + harnessBase}, h.sent())
	req, body := ag.request(0)
	assert.Equal(t, "Bearer cloud-token", req.Header.Get("Authorization"))
	session := req.Header.Get(registrydomain.AgentCoreSessionHeader)
	assert.GreaterOrEqual(t, len(session), 33)
	assert.JSONEq(t, `{"messages":[{"role":"user","content":[{"text":"Hello!\n{\"city\":\"Paris\"}"}]}]}`, string(body))
	_, owned := h.store.owner(h.harness, a2a.ScopeContext, contextID)
	assert.True(t, owned)

	// The next turn names the context and runs in the same harness session.
	_, rpcErr = h.send(t, rpcRequest("message/send", `{"message":{"messageId":"m-2","role":"user","contextId":"`+contextID+`","parts":[{"kind":"text","text":"And tomorrow?"}]}}`), nil)
	require.Nil(t, rpcErr)
	next, _ := ag.request(1)
	assert.Equal(t, session, next.Header.Get(registrydomain.AgentCoreSessionHeader))
}

func TestHarnessErrorsComeBackFromTheAgent(t *testing.T) {
	t.Parallel()
	for _, events := range [][]harnessEvent{
		{{"event", "messageStart", `{"role":"assistant"}`}, {"exception", "runtimeClientError", `{"message":"tool failed"}`}},
		{{"event", "runtimeClientError", `{"message":"tool failed"}`}},
	} {
		ag := newAgent(t, eventStream(t, events...))
		h := newHostedHarness(t, ag, a2a.Version03, harnessTarget(), builtCard)
		_, rpcErr := h.send(t, rpcRequest("message/send", sendHello), nil)
		require.NotNil(t, rpcErr)
		assert.Equal(t, int64(-32603), rpcErr.Code)
		assert.Equal(t, "tool failed", rpcErr.Message)
	}
}

func TestTranslatedAgentsRefuseWhatTheyCannotTake(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, eventStream(t))
	h := newHostedHarness(t, ag, a2a.Version03, harnessTarget(), builtCard)

	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"messageId":"m-1","role":"user","parts":[{"kind":"file","file":{"uri":"https://x/f.pdf"}}]}}`), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, int64(-32005), rpcErr.Code)

	_, rpcErr = h.send(t, rpcRequest("message/stream", sendHello), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.UnsupportedOperation(a2a.Version03).Code, rpcErr.Code)
	assert.Empty(t, h.sent())
}

func databricksTarget(locator *registrydomain.DatabricksLocator) *registrydomain.A2ATarget {
	return &registrydomain.A2ATarget{
		Provider:   registrydomain.A2AProviderDatabricks,
		Databricks: locator,
		Auth:       &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer dapi-token"},
	}
}

func TestDatabricksSendsTheResponsesShape(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{"output":[{"type":"function_call","name":"search"},`+
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Two flats match."}]}]}`)))
	h := newHostedHarness(t, ag, a2a.Version03, databricksTarget(&registrydomain.DatabricksLocator{
		WorkspaceURL: "https://adb-1234567890123456.7.azuredatabricks.net", ServingEndpoint: "agents_flats",
	}), builtCard)

	result, rpcErr := h.send(t, rpcRequest("message/send", sendHello), nil)
	require.Nil(t, rpcErr)
	text, contextID := answerText(t, result)
	assert.Equal(t, "Two flats match.", text)

	assert.Equal(t, []string{"POST https://adb-1234567890123456.7.azuredatabricks.net/serving-endpoints/agents_flats/invocations"}, h.sent())
	req, body := ag.request(0)
	assert.Equal(t, "Bearer dapi-token", req.Header.Get("Authorization"))
	assert.JSONEq(t, `{"input":[{"role":"user","content":"Hello!\n{\"city\":\"Paris\"}"}],"context":{"conversation_id":"`+contextID+`"}}`, string(body))
}

func TestDatabricksAppAndErrors(t *testing.T) {
	t.Parallel()
	app := &registrydomain.DatabricksLocator{WorkspaceURL: "https://acme.cloud.databricks.com", AppURL: "https://flats-123.aws.databricksapps.com"}
	cases := []struct {
		status int
		code   int64
		reason string
		msg    string
	}{
		{status: http.StatusBadRequest, code: -32603, msg: "input is required"},
		{status: http.StatusForbidden, code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamAuthFailed},
		{status: http.StatusServiceUnavailable, code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamError},
	}
	for _, tc := range cases {
		ag := newAgent(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.Copy(w, strings.NewReader(`{"error_code":"BAD_REQUEST","message":"input is required"}`))
		})
		h := newHostedHarness(t, ag, a2a.Version03, databricksTarget(app), builtCard)
		_, rpcErr := h.send(t, rpcRequest("message/send", sendHello), nil)
		require.NotNil(t, rpcErr, tc.status)
		assert.Equal(t, tc.code, rpcErr.Code, tc.status)
		if tc.reason != "" {
			assert.Equal(t, tc.reason, reasonOf(t, rpcErr), tc.status)
		}
		if tc.msg != "" {
			assert.Equal(t, tc.msg, rpcErr.Message)
		}
		assert.Equal(t, []string{"POST https://flats-123.aws.databricksapps.com/responses"}, h.sent())
	}
}
