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
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type httpUpstream struct{}

func (httpUpstream) Do(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

type executorFunc func(ctx context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error)

func (f executorFunc) RunStage(ctx context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
	return f(ctx, in)
}

func allow(context.Context, appplugins.StageInput) (*appplugins.StageOutcome, error) {
	return &appplugins.StageOutcome{}, nil
}

// agent is an A2A agent that answers every call with its handler and records
// what reached it.
type agent struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
}

func newAgent(t *testing.T, handler http.HandlerFunc) *agent {
	t.Helper()
	a := &agent{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.requests = append(a.requests, r)
		a.bodies = append(a.bodies, body)
		a.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *agent) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.requests)
}

func (a *agent) request(i int) (*http.Request, []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests[i], a.bodies[i]
}

func answer(raw []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}
}

func a2aRegistry(t *testing.T, v a2a.Version, url string) *registrydomain.Registry {
	t.Helper()
	return &registrydomain.Registry{
		ID:      ids.New[ids.RegistryKind](),
		Name:    "Travel planner",
		Type:    registrydomain.TypeA2A,
		Enabled: true,
		A2ATarget: &registrydomain.A2ATarget{
			Provider:        registrydomain.A2AProviderGeneric,
			ProtocolVersion: v,
			URL:             url,
			Card:            readFixture(t, "card."+versions[v]+".json"),
			Auth:            &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone},
		},
	}
}

func a2aConsumer(regs ...*registrydomain.Registry) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Name:      "research-bot",
			Slug:      "research-bot",
			Type:      consumerdomain.TypeA2A,
		},
		Registries: regs,
	}
}

type harness struct {
	forwarder *a2a.Forwarder
	store     *memStore
	consumer  *appconsumer.RoutableConsumer
	agent     *registrydomain.Registry
	principal *identity.Principal
}

func newHarness(t *testing.T, v a2a.Version, url string, exec executorFunc) *harness {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	reg := a2aRegistry(t, v, url)
	rc := a2aConsumer(reg)
	store := newMemStore()
	return &harness{
		forwarder: a2a.NewForwarder(httpUpstream{}, a2a.NewPluginRunner(exec, logger), a2a.NewCredentials(nil, nil, nil, false), store, logger),
		store:     store,
		consumer:  rc,
		agent:     reg,
		principal: &identity.Principal{Subject: consumerdomain.AppSubject(rc.Consumer.ID), Method: identity.MethodAPIKey},
	}
}

func (h *harness) call(t *testing.T, body []byte, header http.Header) *a2a.Call {
	t.Helper()
	req, rpcErr := a2a.Decode(body)
	require.Nil(t, rpcErr)
	if header == nil {
		header = http.Header{}
	}
	return &a2a.Call{Consumer: h.consumer, Agent: h.agent, Principal: h.principal, Request: req, Body: body, Header: header}
}

func (h *harness) send(t *testing.T, body []byte, header http.Header) (json.RawMessage, *a2a.RPCError) {
	t.Helper()
	x, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, body, header))
	if rpcErr != nil {
		return nil, rpcErr
	}
	return x.Send(context.Background())
}

func rpcRequest(method, params string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":7,"method":"` + method + `","params":` + params + `}`)
}

func reasonOf(t *testing.T, e *a2a.RPCError) string {
	t.Helper()
	var data struct {
		Reason string `json:"reason"`
		Plugin string `json:"plugin"`
	}
	require.NoError(t, json.Unmarshal(e.Data, &data))
	return data.Reason
}

func TestForwarderSendsOnlyTheRegistryCredential(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		ag := newAgent(t, answer(readFixture(t, prefix+".send.response.json")))
		h := newHarness(t, v, ag.URL, allow)
		h.agent.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "X-Agent-Key", Value: "s3cret"}
		h.agent.A2ATarget.Headers = map[string]string{"X-Tenant": "acme"}
		inbound := http.Header{}
		inbound.Set("X-AG-API-Key", "k1")
		inbound.Set("Authorization", "Bearer t1")
		inbound.Set("Cookie", "session=1")
		inbound.Set("X-Forwarded-For", "10.0.0.1")
		inbound.Set("A2A-Extensions", "https://ext.example/v1")
		inbound.Set("X-A2A-Extensions", "https://ext.example/v1")
		body := readFixture(t, prefix+".send.request.json")

		result, rpcErr := h.send(t, body, inbound)
		require.Nil(t, rpcErr, prefix)
		assert.JSONEq(t, string(resultOf(t, readFixture(t, prefix+".send.response.json"))), string(result), prefix)

		req, got := ag.request(0)
		assert.Equal(t, body, got, prefix)
		want := []string{"Accept", "Accept-Encoding", "Content-Length", "Content-Type", "User-Agent", "X-Agent-Key", "X-Tenant"}
		if v == a2a.Version10 {
			want = append(want, "A2a-Extensions", "A2a-Version")
			assert.Equal(t, "1.0", req.Header.Get("A2A-Version"))
		} else {
			want = append(want, "X-A2a-Extensions")
		}
		var names []string
		for name := range req.Header {
			names = append(names, name)
		}
		assert.ElementsMatch(t, want, names, prefix)
		assert.Equal(t, "s3cret", req.Header.Get("X-Agent-Key"))
		assert.Equal(t, "application/json", req.Header.Get("Accept"))
	}
}

func TestForwarderRefusesWithoutCallingTheAgent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		v       a2a.Version
		body    []byte
		allowed []string
		card    string
		code    int64
	}{
		{name: "1.0 method on a 0.3 agent", v: a2a.Version03, body: rpcRequest("SendMessage", `{}`), code: a2a.CodeMethodNotFound},
		{name: "unknown method", v: a2a.Version10, body: rpcRequest("tasks/get", `{"id":"t"}`), code: a2a.CodeMethodNotFound},
		{name: "push config", v: a2a.Version03, body: rpcRequest("tasks/pushNotificationConfig/set", `{"taskId":"t","pushNotificationConfig":{"url":"https://hook"}}`), code: a2a.CodePushNotificationNotSupported},
		{name: "list tasks", v: a2a.Version10, body: rpcRequest("ListTasks", `{}`), code: a2a.CodeUnsupportedOperation},
		{name: "extended card", v: a2a.Version10, body: rpcRequest("GetExtendedAgentCard", `{}`), code: a2a.CodeExtendedCardNotConfigured},
		{name: "outside allowed methods", v: a2a.Version03, body: rpcRequest("tasks/get", `{"id":"t"}`), allowed: []string{"message/send"}, code: a2a.CodeMethodNotFound},
		{name: "stream on a card without streaming", v: a2a.Version10, body: rpcRequest("SendStreamingMessage", `{"message":{"parts":[]}}`), card: `{"name":"x","capabilities":{}}`, code: a2a.CodeUnsupportedOperation},
		{name: "send without a message", v: a2a.Version03, body: rpcRequest("message/send", `{}`), code: a2a.CodeInvalidParams},
	}
	for _, tc := range cases {
		ag := newAgent(t, answer(nil))
		h := newHarness(t, tc.v, ag.URL, allow)
		h.agent.A2ATarget.AllowedMethods = tc.allowed
		if tc.card != "" {
			h.agent.A2ATarget.Card = []byte(tc.card)
		}
		_, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, tc.body, nil))
		require.NotNil(t, rpcErr, tc.name)
		assert.Equal(t, tc.code, rpcErr.Code, tc.name)
		assert.Zero(t, ag.calls(), tc.name)
	}
}

func TestForwarderUpstreamFailures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		handler http.HandlerFunc
		reason  string
	}{
		{name: "not JSON", handler: answer([]byte("<html>")), reason: a2a.ReasonInvalidUpstreamResponse},
		{name: "not JSON-RPC", handler: answer([]byte(`{"ok":true}`)), reason: a2a.ReasonInvalidUpstreamResponse},
		{name: "unknown result", handler: answer([]byte(`{"jsonrpc":"2.0","id":7,"result":{"kind":"other"}}`)), reason: a2a.ReasonInvalidUpstreamResponse},
		{name: "error status", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}, reason: a2a.ReasonUpstreamError},
		{name: "too large", handler: answer(append([]byte(`{"jsonrpc":"2.0","id":7,"result":"`), bytes.Repeat([]byte("a"), 8<<20)...)), reason: a2a.ReasonResponseTooLarge},
	}
	for _, tc := range cases {
		ag := newAgent(t, tc.handler)
		h := newHarness(t, a2a.Version03, ag.URL, allow)
		_, rpcErr := h.send(t, readFixture(t, "v03.send.request.json"), nil)
		require.NotNil(t, rpcErr, tc.name)
		assert.Equal(t, a2a.CodeGatewayFailure, rpcErr.Code, tc.name)
		assert.Equal(t, tc.reason, reasonOf(t, rpcErr), tc.name)
	}

	h := newHarness(t, a2a.Version03, "http://127.0.0.1:1", allow)
	_, rpcErr := h.send(t, readFixture(t, "v03.send.request.json"), nil)
	assert.Equal(t, a2a.ReasonUpstreamUnreachable, reasonOf(t, rpcErr))
}

func TestForwarderUpstreamTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	ag := newAgent(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	x, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, readFixture(t, "v03.send.request.json"), nil))
	require.Nil(t, rpcErr)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, rpcErr = x.Send(ctx)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.ReasonUpstreamTimeout, reasonOf(t, rpcErr))
}

func TestForwarderPassesTheAgentErrorThrough(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(readFixture(t, "v10.task_not_found.response.json")))
	h := newHarness(t, a2a.Version10, ag.URL, allow)
	h.store.set(h, a2a.ScopeTask, "3cad155d-0af8-4d33-9734-4dc86c76004c", h.owner())
	_, rpcErr := h.send(t, readFixture(t, "v10.get.request.json"), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.CodeTaskNotFound, rpcErr.Code)
	assert.Equal(t, 1, ag.calls())
}

func TestForwarderPolicies(t *testing.T) {
	t.Parallel()
	block := func(stage policy.Stage, pe *appplugins.PluginError) executorFunc {
		return func(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
			if in.Stage == stage {
				return nil, pe
			}
			return &appplugins.StageOutcome{}, nil
		}
	}
	cases := []struct {
		name   string
		exec   executorFunc
		code   int64
		reason string
		calls  int
	}{
		{name: "request blocked", exec: block(policy.StagePreRequest, &appplugins.PluginError{StatusCode: http.StatusRequestEntityTooLarge, Plugin: "request_size_limiter"}), code: a2a.CodePolicyBlocked, reason: a2a.ReasonPolicyBlocked},
		{name: "rate limited", exec: block(policy.StagePreRequest, &appplugins.PluginError{StatusCode: http.StatusTooManyRequests, Headers: map[string][]string{"Retry-After": {"30"}}, Plugin: "rate_limiter"}), code: a2a.CodeRateLimited},
		{name: "mask", exec: block(policy.StagePreRequest, &appplugins.PluginError{StatusCode: http.StatusForbidden, Type: appplugins.TypeMaskUnsupported, Plugin: "trustguard"}), code: a2a.CodePolicyBlocked, reason: a2a.ReasonMaskUnsupported},
		{name: "short circuit", exec: func(context.Context, appplugins.StageInput) (*appplugins.StageOutcome, error) {
			return &appplugins.StageOutcome{ShortCircuit: true, StatusCode: http.StatusOK}, nil
		}, code: a2a.CodePolicyBlocked, reason: a2a.ReasonPolicyBlocked},
		{name: "response blocked", exec: block(policy.StagePreResponse, &appplugins.PluginError{StatusCode: http.StatusForbidden, Plugin: "trustguard"}), code: a2a.CodePolicyBlocked, reason: a2a.ReasonPolicyBlocked, calls: 1},
	}
	for _, tc := range cases {
		ag := newAgent(t, answer(readFixture(t, "v03.send.response.json")))
		h := newHarness(t, a2a.Version03, ag.URL, tc.exec)
		_, rpcErr := h.send(t, readFixture(t, "v03.send.request.json"), nil)
		require.NotNil(t, rpcErr, tc.name)
		assert.Equal(t, tc.code, rpcErr.Code, tc.name)
		if tc.reason != "" {
			assert.Equal(t, tc.reason, reasonOf(t, rpcErr), tc.name)
		}
		assert.Equal(t, tc.calls, ag.calls(), tc.name)
	}
}

func TestForwarderFailsOpenOnAPolicyFailure(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(readFixture(t, "v03.send.response.json")))
	h := newHarness(t, a2a.Version03, ag.URL, func(context.Context, appplugins.StageInput) (*appplugins.StageOutcome, error) {
		return nil, io.ErrUnexpectedEOF
	})
	_, rpcErr := h.send(t, readFixture(t, "v03.send.request.json"), nil)
	require.Nil(t, rpcErr)
	assert.Equal(t, 1, ag.calls())
}

// Plugins see the normalised parts and the length of the body the caller
// sent, never the JSON-RPC envelope.
func TestForwarderPluginInput(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := map[policy.Stage]appplugins.StageInput{}
	ag := newAgent(t, answer(readFixture(t, "v10.send.response.json")))
	h := newHarness(t, a2a.Version10, ag.URL, func(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
		mu.Lock()
		seen[in.Stage] = in
		mu.Unlock()
		return &appplugins.StageOutcome{}, nil
	})
	body := readFixture(t, "v10.send.request.json")
	_, rpcErr := h.send(t, body, http.Header{"X-Team": {"blue"}})
	require.Nil(t, rpcErr)

	pre := seen[policy.StagePreRequest].Request
	require.NotNil(t, pre)
	assert.True(t, pre.A2A)
	assert.Equal(t, "A2A", pre.ConsumerType)
	assert.Equal(t, "SendMessage", pre.A2AMethod)
	assert.Equal(t, h.agent.ID.String(), pre.RegistryID)
	assert.Equal(t, []string{"blue"}, pre.Headers["X-Team"])
	assert.Equal(t, []string{strconv.Itoa(len(body))}, pre.Headers["Content-Length"])
	var normalised struct {
		Method string     `json:"method"`
		Agent  string     `json:"agent"`
		Parts  []a2a.Part `json:"parts"`
	}
	require.NoError(t, json.Unmarshal(pre.Body, &normalised))
	assert.Equal(t, "SendMessage", normalised.Method)
	assert.Equal(t, "Travel planner", normalised.Agent)
	assert.Len(t, normalised.Parts, 4)

	resp := seen[policy.StagePreResponse].Response
	require.NotNil(t, resp)
	require.NoError(t, json.Unmarshal(resp.Body, &normalised))
	assert.Equal(t, a2a.PartText, normalised.Parts[0].Type)
	assert.Equal(t, "done", normalised.Parts[0].Text)
}

func TestResolveAgent(t *testing.T) {
	t.Parallel()
	first := a2aRegistry(t, a2a.Version03, "https://a.example")
	second := a2aRegistry(t, a2a.Version03, "https://b.example")
	disabled := a2aRegistry(t, a2a.Version03, "https://c.example")
	disabled.Name, disabled.Enabled = "Disabled", false
	rc := a2aConsumer(first, second, disabled)

	_, ok := a2a.ResolveAgent(rc, "Travel planner")
	assert.False(t, ok, "two agents share the name")
	got, ok := a2a.ResolveAgent(rc, second.ID.String())
	require.True(t, ok)
	assert.Same(t, second, got)
	_, ok = a2a.ResolveAgent(rc, "Disabled")
	assert.False(t, ok)
	_, ok = a2a.ResolveAgent(rc, disabled.ID.String())
	assert.False(t, ok)

	rc.Registries = []*registrydomain.Registry{first}
	got, ok = a2a.ResolveAgent(rc, "Travel planner")
	require.True(t, ok)
	assert.Same(t, first, got)
}
