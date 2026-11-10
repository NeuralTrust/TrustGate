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

package trustguard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const testAgentSecurityIntegrationID = "22222222-2222-4222-8222-222222222222"

// agentSecurityWireRequest is AgentSecurity's /v1/evaluate decoder: unknown fields are a 400.
type agentSecurityWireRequest struct {
	OriginalRequest *struct {
		IP      string              `json:"ip,omitempty"`
		Headers map[string][]string `json:"headers,omitempty"`
	} `json:"original_request,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	Direction      string          `json:"direction"`
	Protocol       string          `json:"protocol"`
	GatewayID      string          `json:"gateway_id"`
	IntegrationKey string          `json:"integration_key"`
	SessionID      string          `json:"session_id"`
	ApplicationID  string          `json:"application_id"`
	Attributes     map[string]any  `json:"attributes"`
}

type fakeAgentSecurity struct {
	mu       sync.Mutex
	status   int
	delay    time.Duration
	answer   string
	tokens   []map[string]any
	requests []agentSecurityWireRequest
	invalid  int
	// refuse answers every gateway-only token request with this status and code.
	refuseStatus int
	refuseCode   string
}

func (f *fakeAgentSecurity) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.tokens = append(f.tokens, body)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if _, explicit := body["integration_id"]; !explicit && f.refuseStatus != 0 {
				w.WriteHeader(f.refuseStatus)
				_, _ = w.Write([]byte(`{"error":"` + f.refuseCode + `"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "agentSecurity-token", TokenType: "Bearer", ExpiresIn: 3600})
			return
		}
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				return
			}
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var body agentSecurityWireRequest
		err := dec.Decode(&body)
		f.mu.Lock()
		if err != nil || r.Header.Get("Authorization") != "Bearer agentSecurity-token" {
			f.invalid++
			f.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.requests = append(f.requests, body)
		f.mu.Unlock()
		status := f.status
		if status == 0 {
			status = http.StatusOK
		}
		answer := f.answer
		if answer == "" {
			answer = `{"status":"allow","findings":[],"mode":"enforce"}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}
}

func (f *fakeAgentSecurity) seen() ([]agentSecurityWireRequest, []map[string]any, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]agentSecurityWireRequest(nil), f.requests...), append([]map[string]any(nil), f.tokens...), f.invalid
}

func newAgentSecurityServer(t *testing.T, f *fakeAgentSecurity) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

func newAgentSecurityPlugin(t *testing.T, v2URL, agentSecurityURL string, gateways map[string]string) *Plugin {
	t.Helper()
	p := New(adapter.NewRegistry(), v2URL, testTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)),
		WithAgentSecurity(AgentSecurityConfig{BaseURL: agentSecurityURL, Timeout: time.Second, ClientID: "agentSecurity-client", ClientSecret: "agentSecurity-secret", Gateways: gateways}))
	t.Cleanup(p.agentSecurity.wait)
	return p
}

func TestAgentSecurityOffSendsNothing(t *testing.T) {
	t.Parallel()
	for name, gateways := range map[string]map[string]string{
		"no gateways":     nil,
		"another gateway": {"gw-other": ""},
		"empty map":       {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			agentSecurity := &fakeAgentSecurity{}
			p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, gateways)

			_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
			require.NoError(t, err)
			p.agentSecurity.wait()

			requests, tokens, invalid := agentSecurity.seen()
			assert.Equal(t, 1, v2.count())
			assert.Empty(t, requests)
			assert.Empty(t, tokens)
			assert.Zero(t, invalid)
		})
	}
}

func TestAgentSecurityCopiesTheEvaluationInGuardsShape(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})
	req := requestContext()
	req.ConsumerName = "Support bot"

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	p.agentSecurity.wait()

	requests, tokens, invalid := agentSecurity.seen()
	require.Zero(t, invalid)
	require.Len(t, requests, 1)
	got := requests[0]
	sent := v2.captured()
	assert.Equal(t, "gw-test", got.GatewayID)
	assert.Empty(t, got.IntegrationKey)
	assert.Equal(t, "consumer-9", got.ApplicationID)
	assert.Equal(t, protocolLLM, got.Protocol)
	assert.Equal(t, directionInput, got.Direction)
	assert.Equal(t, "sess-123", got.SessionID)
	assert.JSONEq(t, string(sent.Payload), string(got.Payload))
	assert.NotContains(t, got.Attributes, "consumer")
	assert.Equal(t, map[string]any{"name": "Support bot"}, got.Attributes["application"])
	assert.Equal(t, map[string]any{"name": "gpt-4o", "provider": "openai", "requested_name": "gpt-4o-mini"}, got.Attributes["model"])
	assert.Equal(t, GuardModel{Name: "gpt-4o-mini", Provider: "openai"}, sent.Attributes.Model)

	require.Len(t, tokens, 1)
	assert.Equal(t, testCollectorID, tokens[0]["integration_id"])
	assert.NotContains(t, tokens[0], "collector_id")
	assert.Equal(t, "gw-test", tokens[0]["gateway_id"])
	assert.Equal(t, tokenScopePlatform, tokens[0]["scope"])
	assert.Equal(t, "agentSecurity-client", tokens[0]["client_id"])
}

func TestAgentSecurityIntegrationOverrideAndTokenCache(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": testAgentSecurityIntegrationID})

	for range 3 {
		_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
		require.NoError(t, err)
		p.agentSecurity.wait()
	}

	requests, tokens, _ := agentSecurity.seen()
	assert.Len(t, requests, 3)
	require.Len(t, tokens, 1, "the token is cached like TrustGuard's")
	assert.Equal(t, testAgentSecurityIntegrationID, tokens[0]["integration_id"])
}

func TestAgentSecurityCopiesMCPWithItsServer(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		code string
		want string
	}{
		"catalog server is its code":    {code: "com.asana/mcp", want: "com.asana/mcp"},
		"custom server is its registry": {want: "reg-1"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			agentSecurity := &fakeAgentSecurity{}
			p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})
			req := mcpRequestContext()
			req.MCPServerID = "reg-1"
			req.MCPServerCode = tc.code

			_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
			require.NoError(t, err)
			p.agentSecurity.wait()

			requests, _, invalid := agentSecurity.seen()
			require.Zero(t, invalid)
			require.Len(t, requests, 1)
			assert.Equal(t, protocolMCP, requests[0].Protocol)
			assert.Equal(t, "consumer-mcp", requests[0].ApplicationID)
			assert.Equal(t, map[string]any{"id": tc.want}, requests[0].Attributes["mcp_server"])
		})
	}
}

func TestAgentSecuritySkipsA2A(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})
	req := requestContext()
	req.ConsumerType = protocolA2A

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	p.agentSecurity.wait()

	requests, tokens, _ := agentSecurity.seen()
	assert.Equal(t, protocolA2A, v2.captured().Protocol)
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestAgentSecurityNeverDecides(t *testing.T) {
	t.Parallel()
	cases := map[string]*fakeAgentSecurity{
		"agentsecurity blocks":       {answer: `{"status":"block","findings":[],"mode":"enforce"}`},
		"agentsecurity refuses":      {status: http.StatusBadRequest},
		"agentsecurity fails":        {status: http.StatusInternalServerError},
		"agentsecurity rate limited": {status: http.StatusTooManyRequests},
	}
	for name, agentSecurity := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
			require.NoError(t, err)
			assert.Equal(t, passThrough(), res)
			p.agentSecurity.wait()
		})
	}

	t.Run("v2 blocks, agentsecurity allows", func(t *testing.T) {
		t.Parallel()
		v2 := &fakeGuard{response: GuardResponse{Status: statusBlock}}
		p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, &fakeAgentSecurity{}).URL, map[string]string{"gw-test": ""})

		res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
		assert.Nil(t, res)
		_, blocked := appplugins.AsPluginError(err)
		assert.True(t, blocked)
		p.agentSecurity.wait()
	})
}

func TestAgentSecuritySlowOrDownDoesNotDelay(t *testing.T) {
	t.Parallel()
	slow := &fakeAgentSecurity{delay: 3 * time.Second}
	cases := map[string]string{
		"slow": newAgentSecurityServer(t, slow).URL,
		"down": "http://127.0.0.1:1",
	}
	for name, agentSecurityURL := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := newAgentSecurityPlugin(t, newServer(t, v2).URL, agentSecurityURL, map[string]string{"gw-test": ""})

			start := time.Now()
			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
			elapsed := time.Since(start)
			require.NoError(t, err)
			assert.Equal(t, passThrough(), res)
			assert.Less(t, elapsed, 500*time.Millisecond)
		})
	}
}

func TestAgentSecurityDropsPastTheBound(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})
	for range cap(p.agentSecurity.slots) {
		p.agentSecurity.slots <- struct{}{}
	}

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
	require.NoError(t, err)
	for range cap(p.agentSecurity.slots) {
		<-p.agentSecurity.slots
	}
	p.agentSecurity.wait()

	requests, tokens, _ := agentSecurity.seen()
	assert.Equal(t, 1, v2.count())
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestAgentSecurityCopiesEachStreamBlock(t *testing.T) {
	t.Parallel()
	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPlugin(t, newSegmentServer(t, g).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})
	in := segmentInput(t, streamingSettings(nil))
	in.Request.SentModel = "gpt-4.1"

	segments := []appplugins.StreamSegment{
		{StreamID: "h", Seq: 1, Accumulated: "Hello"},
		{StreamID: "h", Seq: 2, Final: true, Accumulated: "Hello world"},
	}
	for _, seg := range segments {
		_, err := p.InspectSegment(segmentTraceContext(), in, seg)
		require.NoError(t, err)
		p.agentSecurity.wait()
	}

	requests, _, invalid := agentSecurity.seen()
	require.Zero(t, invalid)
	require.Len(t, requests, len(segments))
	calls := g.calls()
	for i, got := range requests {
		assert.Equal(t, directionOutput, got.Direction)
		assert.Equal(t, "gpt-4.1", got.Attributes["model"].(map[string]any)["name"])
		stream, _ := got.Attributes["stream"].(map[string]any)
		require.NotNil(t, stream)
		assert.Equal(t, calls[i].Attributes.Stream.ID, stream["id"])
		assert.Equal(t, calls[i].Attributes.Stream.Final, stream["final"])
	}
}

func TestAgentSecurityPayloadIsACopy(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	req := toAgentSecurityRequest(GuardRequest{Payload: payload}, nil)
	copy(payload, bytes.Repeat([]byte("x"), len(payload)))
	assert.JSONEq(t, `{"messages":[{"role":"user","content":"hi"}]}`, string(req.Payload))
}

func TestAgentSecurityModelIdentity(t *testing.T) {
	t.Parallel()
	const resolved = "anthropic.claude-sonnet-4-5-20250929-v1:0"
	cases := []struct {
		ref, body, defaultModel, sent, resolved, native, want string
	}{
		{ref: "@openai/gpt-4o", body: `{"model":"gpt-4o"}`, want: "gpt-4o"},
		{ref: "pool:chat", body: `{}`, defaultModel: "gpt-4o", want: "gpt-4o"},
		{ref: "auto", body: `{}`, defaultModel: "gpt-4o", want: "gpt-4o"},
		{ref: "gpt-4o", body: `{"model":"gpt-4o"}`, want: "gpt-4o"},
		{body: `{}`, defaultModel: "gpt-4o", want: "gpt-4o"},
		{ref: "pool:chat", body: `{}`, defaultModel: "old", sent: "gpt-4.1", want: "gpt-4.1"},
		{ref: "arn:aws:bedrock:us-east-1:123:application-inference-profile/x", resolved: resolved, want: resolved},
		{native: resolved, want: resolved},
		{native: "arn:aws:bedrock:us-east-1::foundation-model/" + resolved, want: resolved},
		{native: "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/x"},
		{body: `{"model":"auto"}`},
		{body: `{"model":"pool:chat"}`},
		{body: `{"model":"@openai/gpt-4o"}`},
	}
	for _, tc := range cases {
		t.Run(tc.ref+tc.native+tc.body+tc.sent, func(t *testing.T) {
			t.Parallel()
			req := &infracontext.RequestContext{
				Provider: " OpenAI ", RequestedModel: tc.ref, Body: []byte(tc.body),
				DefaultModel: tc.defaultModel, SentModel: tc.sent, ResolvedModel: tc.resolved,
			}
			if tc.native != "" {
				req.BedrockNative = &infracontext.BedrockNativeTarget{ModelID: tc.native}
			}
			direction := directionInput
			if tc.sent != "" {
				direction = directionOutput
			}
			got := toAgentSecurityRequest(GuardRequest{Direction: direction}, req).Attributes.Model
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.Name)
			assert.Equal(t, "openai", got.Provider)
			assert.Equal(t, tc.ref, got.RequestedName)
		})
	}
}

func TestAgentSecurityNativeMCPToolOnBothDirections(t *testing.T) {
	t.Parallel()
	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		t.Run(string(stage), func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			agentSecurity := &fakeAgentSecurity{}
			p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": ""})
			req := mcpRequestContext()
			req.MCPServerID, req.MCPServerName, req.MCPTool = "shelf-id", "Analytics", "run_query"
			var response *infracontext.ResponseContext
			if stage == policy.StagePreResponse {
				response = &infracontext.ResponseContext{Body: []byte(`{"content":[{"type":"text","text":"42"}]}`)}
			}
			_, err := p.Execute(context.Background(), execInput(stage, policy.ModeEnforce, settings(""), req, response))
			require.NoError(t, err)
			p.agentSecurity.wait()
			requests, _, invalid := agentSecurity.seen()
			require.Zero(t, invalid)
			require.Len(t, requests, 1)
			assert.Equal(t, map[string]any{"id": "shelf-id", "name": "Analytics", "tool": map[string]any{"name": "run_query"}}, requests[0].Attributes["mcp_server"])
			assert.NotContains(t, requests[0].Attributes, "tool")
			assert.NotContains(t, requests[0].Attributes, "model")
			raw, err := json.Marshal(v2.captured())
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "run_query")
			assert.NotContains(t, string(raw), "Analytics")
			if stage == policy.StagePreRequest {
				assert.JSONEq(t, string(v2.captured().Payload), string(requests[0].Payload))
			}
		})
	}
}

func TestAgentSecurityFailureReason(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		err  error
		want string
	}{
		"bad request":  {&agentSecurityStatusError{status: http.StatusBadRequest}, "bad_request"},
		"unauthorized": {&agentSecurityStatusError{status: http.StatusForbidden}, failureReasonUnauthorized},
		"token":        {&authRejectedError{status: http.StatusBadRequest}, failureReasonUnauthorized},
		"rate limited": {&agentSecurityStatusError{status: http.StatusTooManyRequests}, "rate_limited"},
		"server":       {&agentSecurityStatusError{status: http.StatusBadGateway}, "status_502"},
		"timeout":      {context.DeadlineExceeded, failureReasonTimeout},
		"transport":    {assert.AnError, failureReasonTransport},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, agentSecurityFailureReason(tc.err))
		})
	}
}
