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
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const testV3IntegrationID = "22222222-2222-4222-8222-222222222222"

// v3WireRequest is Guard's /v1/evaluate decoder: unknown fields are a 400.
type v3WireRequest struct {
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

type fakeV3 struct {
	mu       sync.Mutex
	status   int
	delay    time.Duration
	answer   string
	tokens   []map[string]any
	requests []v3WireRequest
	invalid  int
}

func (f *fakeV3) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.tokens = append(f.tokens, body)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "v3-token", TokenType: "Bearer", ExpiresIn: 3600})
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
		var body v3WireRequest
		err := dec.Decode(&body)
		f.mu.Lock()
		if err != nil || r.Header.Get("Authorization") != "Bearer v3-token" {
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

func (f *fakeV3) seen() ([]v3WireRequest, []map[string]any, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]v3WireRequest(nil), f.requests...), append([]map[string]any(nil), f.tokens...), f.invalid
}

func newV3Server(t *testing.T, f *fakeV3) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

func newV3Plugin(t *testing.T, v2URL, v3URL string, gateways map[string]string) *Plugin {
	t.Helper()
	p := New(adapter.NewRegistry(), v2URL, testTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)),
		WithV3(V3Config{BaseURL: v3URL, Timeout: time.Second, ClientID: "v3-client", ClientSecret: "v3-secret", Gateways: gateways}))
	t.Cleanup(p.v3.wait)
	return p
}

func TestV3OffSendsNothing(t *testing.T) {
	t.Parallel()
	for name, gateways := range map[string]map[string]string{
		"no gateways":     nil,
		"another gateway": {"gw-other": ""},
		"empty map":       {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			v3 := &fakeV3{}
			p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, gateways)

			_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
			require.NoError(t, err)
			p.v3.wait()

			requests, tokens, invalid := v3.seen()
			assert.Equal(t, 1, v2.count())
			assert.Empty(t, requests)
			assert.Empty(t, tokens)
			assert.Zero(t, invalid)
		})
	}
}

func TestV3CopiesTheEvaluationInGuardsShape(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": ""})
	req := requestContext()
	req.ConsumerName = "Support bot"

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	p.v3.wait()

	requests, tokens, invalid := v3.seen()
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
	assert.Equal(t, map[string]any{"name": "gpt-4o-mini", "provider": "openai"}, got.Attributes["model"])

	require.Len(t, tokens, 1)
	assert.Equal(t, testCollectorID, tokens[0]["integration_id"])
	assert.NotContains(t, tokens[0], "collector_id")
	assert.Equal(t, "gw-test", tokens[0]["gateway_id"])
	assert.Equal(t, tokenScopePlatform, tokens[0]["scope"])
	assert.Equal(t, "v3-client", tokens[0]["client_id"])
}

func TestV3IntegrationOverrideAndTokenCache(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": testV3IntegrationID})

	for range 3 {
		_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
		require.NoError(t, err)
		p.v3.wait()
	}

	requests, tokens, _ := v3.seen()
	assert.Len(t, requests, 3)
	require.Len(t, tokens, 1, "the token is cached like TrustGuard's")
	assert.Equal(t, testV3IntegrationID, tokens[0]["integration_id"])
}

func TestV3CopiesMCPWithItsServer(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": ""})
	req := mcpRequestContext()
	req.MCPServerID = "reg-1"
	req.MCPServerCode = "com.asana/mcp"

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	p.v3.wait()

	requests, _, invalid := v3.seen()
	require.Zero(t, invalid)
	require.Len(t, requests, 1)
	assert.Equal(t, protocolMCP, requests[0].Protocol)
	assert.Equal(t, "consumer-mcp", requests[0].ApplicationID)
	assert.Equal(t, map[string]any{"id": "reg-1", "code": "com.asana/mcp"}, requests[0].Attributes["mcp_server"])
}

func TestV3SkipsA2A(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": ""})
	req := requestContext()
	req.ConsumerType = protocolA2A

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)
	p.v3.wait()

	requests, tokens, _ := v3.seen()
	assert.Equal(t, protocolA2A, v2.captured().Protocol)
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestV3NeverDecides(t *testing.T) {
	t.Parallel()
	cases := map[string]*fakeV3{
		"v3 blocks":       {answer: `{"status":"block","findings":[],"mode":"enforce"}`},
		"v3 refuses":      {status: http.StatusBadRequest},
		"v3 fails":        {status: http.StatusInternalServerError},
		"v3 rate limited": {status: http.StatusTooManyRequests},
	}
	for name, v3 := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": ""})

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
			require.NoError(t, err)
			assert.Equal(t, passThrough(), res)
			p.v3.wait()
		})
	}

	t.Run("v2 blocks, v3 allows", func(t *testing.T) {
		t.Parallel()
		v2 := &fakeGuard{response: GuardResponse{Status: statusBlock}}
		p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, &fakeV3{}).URL, map[string]string{"gw-test": ""})

		res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
		assert.Nil(t, res)
		_, blocked := appplugins.AsPluginError(err)
		assert.True(t, blocked)
		p.v3.wait()
	})
}

func TestV3SlowOrDownDoesNotDelay(t *testing.T) {
	t.Parallel()
	slow := &fakeV3{delay: 3 * time.Second}
	cases := map[string]string{
		"slow": newV3Server(t, slow).URL,
		"down": "http://127.0.0.1:1",
	}
	for name, v3URL := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := newV3Plugin(t, newServer(t, v2).URL, v3URL, map[string]string{"gw-test": ""})

			start := time.Now()
			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
			elapsed := time.Since(start)
			require.NoError(t, err)
			assert.Equal(t, passThrough(), res)
			assert.Less(t, elapsed, 500*time.Millisecond)
		})
	}
}

func TestV3DropsPastTheBound(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": ""})
	for range cap(p.v3.slots) {
		p.v3.slots <- struct{}{}
	}

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
	require.NoError(t, err)
	for range cap(p.v3.slots) {
		<-p.v3.slots
	}
	p.v3.wait()

	requests, tokens, _ := v3.seen()
	assert.Equal(t, 1, v2.count())
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestV3CopiesEachStreamBlock(t *testing.T) {
	t.Parallel()
	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newSegmentServer(t, g).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": ""})
	in := segmentInput(t, streamingSettings(nil))

	segments := []appplugins.StreamSegment{
		{StreamID: "h", Seq: 1, Accumulated: "Hello"},
		{StreamID: "h", Seq: 2, Final: true, Accumulated: "Hello world"},
	}
	for _, seg := range segments {
		_, err := p.InspectSegment(segmentTraceContext(), in, seg)
		require.NoError(t, err)
		p.v3.wait()
	}

	requests, _, invalid := v3.seen()
	require.Zero(t, invalid)
	require.Len(t, requests, len(segments))
	calls := g.calls()
	for i, got := range requests {
		assert.Equal(t, directionOutput, got.Direction)
		stream, _ := got.Attributes["stream"].(map[string]any)
		require.NotNil(t, stream)
		assert.Equal(t, calls[i].Attributes.Stream.ID, stream["id"])
		assert.Equal(t, calls[i].Attributes.Stream.Final, stream["final"])
	}
}

func TestV3PayloadIsACopy(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	req := toV3Request(GuardRequest{Payload: payload})
	copy(payload, bytes.Repeat([]byte("x"), len(payload)))
	assert.JSONEq(t, `{"messages":[{"role":"user","content":"hi"}]}`, string(req.Payload))
}

func TestV3FailureReason(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		err  error
		want string
	}{
		"bad request":  {&v3StatusError{status: http.StatusBadRequest}, "bad_request"},
		"unauthorized": {&v3StatusError{status: http.StatusForbidden}, failureReasonUnauthorized},
		"token":        {&authRejectedError{status: http.StatusBadRequest}, failureReasonUnauthorized},
		"rate limited": {&v3StatusError{status: http.StatusTooManyRequests}, "rate_limited"},
		"server":       {&v3StatusError{status: http.StatusBadGateway}, "status_502"},
		"timeout":      {context.DeadlineExceeded, failureReasonTimeout},
		"transport":    {assert.AnError, failureReasonTransport},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, v3FailureReason(tc.err))
		})
	}
}
