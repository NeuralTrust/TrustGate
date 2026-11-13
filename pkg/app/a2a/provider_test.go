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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostedUpstream sends each request to the test agent as if it were the
// provider's host, and records the URL the gateway built.
type hostedUpstream struct {
	agent *agent
	mu    *sync.Mutex
	urls  *[]string
}

func (u hostedUpstream) Do(req *http.Request) (*http.Response, error) {
	u.mu.Lock()
	*u.urls = append(*u.urls, req.Method+" "+req.URL.String())
	u.mu.Unlock()
	target, err := url.Parse(u.agent.URL)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme, req.URL.Host, req.Host = target.Scheme, target.Host, ""
	return http.DefaultClient.Do(req)
}

// cloudSigner stands in for the cloud credential: it records the keys it
// signed under and sets a bearer token.
type cloudSigner struct {
	mu   sync.Mutex
	keys []a2a.CacheKey
}

func (s *cloudSigner) Sign(_ context.Context, _ *registrydomain.A2ATarget, key a2a.CacheKey, req *http.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
	req.Header.Set("Authorization", "Bearer cloud-token")
	return nil
}

type hostedHarness struct {
	*harness
	signer *cloudSigner
	mu     sync.Mutex
	urls   []string
}

func (h *hostedHarness) sent() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.urls...)
}

func newHostedHarness(t *testing.T, ag *agent, v a2a.Version, target *registrydomain.A2ATarget, card string) *hostedHarness {
	t.Helper()
	target.ProtocolVersion = v
	target.Card = []byte(card)
	target.Normalize()
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), Name: "Hosted", Type: registrydomain.TypeA2A, Enabled: true, A2ATarget: target}
	rc := a2aConsumer(reg)
	logger := slog.New(slog.DiscardHandler)
	h := &hostedHarness{signer: &cloudSigner{}}
	store := newMemStore()
	upstream := hostedUpstream{agent: ag, mu: &h.mu, urls: &h.urls}
	h.harness = &harness{
		forwarder: a2a.NewForwarder(upstream, a2a.NewPluginRunner(executorFunc(allow), logger), a2a.NewCredentials(nil, nil, h.signer, false), store, logger),
		store:     store,
		consumer:  rc,
		agent:     reg,
		principal: &identity.Principal{Subject: consumerdomain.AppSubject(rc.Consumer.ID), Method: identity.MethodAPIKey},
	}
	return h
}

const foundryCard = `{"name":"Travel planner","capabilities":{"streaming":false}}`

func foundryTarget() *registrydomain.A2ATarget {
	return &registrydomain.A2ATarget{
		Provider:     registrydomain.A2AProviderAzureFoundry,
		AzureFoundry: &registrydomain.FoundryLocator{ProjectEndpoint: "https://acme.services.ai.azure.com/api/projects/travel", AgentName: "planner"},
		Auth:         &registrydomain.MCPAuth{Mode: registrydomain.A2AAuthModeCloud},
		CloudAuth:    &registrydomain.A2ACloudAuth{Azure: &registrydomain.AzureAuth{UseManagedIdentity: true}},
	}
}

func TestFoundryNamesThePinnedVersionAndSignsWithEntra(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		ag := newAgent(t, answer(readFixture(t, prefix+".send.response.json")))
		h := newHostedHarness(t, ag, v, foundryTarget(), foundryCard)
		_, rpcErr := h.send(t, readFixture(t, prefix+".send.request.json"), nil)
		require.Nil(t, rpcErr)

		req, _ := ag.request(0)
		assert.Equal(t, string(v), req.Header.Get("A2A-Version"))
		assert.Equal(t, "Bearer cloud-token", req.Header.Get("Authorization"))
		assert.Equal(t, []string{"POST https://acme.services.ai.azure.com/api/projects/travel/agents/planner/endpoint/protocols/a2a"}, h.sent())
		assert.Equal(t, []a2a.CacheKey{{Registry: h.agent.ID.String(), Version: strconv.FormatInt(h.agent.UpdatedAt.UnixNano(), 10)}}, h.signer.keys)
	}
}

func TestFoundryStreamIsRefusedBeforeTheAgent(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{}`)))
	h := newHostedHarness(t, ag, a2a.Version10, foundryTarget(), foundryCard)
	_, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, readFixture(t, "v10.stream.request.json"), nil))
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.CodeUnsupportedOperation, rpcErr.Code)
	assert.Zero(t, ag.calls())
}

const agentCoreCard = `{"name":"Travel planner","capabilities":{"streaming":true}}`

func agentCoreTarget() *registrydomain.A2ATarget {
	return &registrydomain.A2ATarget{
		Provider:         registrydomain.A2AProviderBedrockAgentCore,
		BedrockAgentCore: &registrydomain.AgentCoreLocator{RuntimeARN: "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/travel-abc"},
		Auth:             &registrydomain.MCPAuth{Mode: registrydomain.A2AAuthModeCloud},
		CloudAuth:        &registrydomain.A2ACloudAuth{AWS: &registrydomain.A2AAWSAuth{}},
	}
}

func sessionOf(t *testing.T, ag *agent, i int) string {
	t.Helper()
	req, _ := ag.request(i)
	return req.Header.Get("X-Amzn-Bedrock-AgentCore-Runtime-Session-Id")
}

func TestAgentCoreCallsTheRuntimeSigned(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHostedHarness(t, ag, a2a.Version03, agentCoreTarget(), agentCoreCard)
	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}]}}`), nil)
	require.Nil(t, rpcErr)

	assert.Equal(t, []string{"POST https://bedrock-agentcore.eu-west-1.amazonaws.com/runtimes/" +
		"arn%3Aaws%3Abedrock-agentcore%3Aeu-west-1%3A123456789012%3Aruntime%2Ftravel-abc/invocations/?qualifier=DEFAULT"}, h.sent())
	req, _ := ag.request(0)
	assert.Equal(t, "Bearer cloud-token", req.Header.Get("Authorization"))
	assert.Len(t, sessionOf(t, ag, 0), 40)
}

func TestAgentCoreSessionFollowsTheContext(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHostedHarness(t, ag, a2a.Version03, agentCoreTarget(), agentCoreCard)
	h.as("u1")
	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}]}}`), nil)
	require.Nil(t, rpcErr)
	_, rpcErr = h.send(t, rpcRequest("message/send", `{"message":{"role":"user","contextId":"`+v03Context+`","parts":[{"kind":"text","text":"again"}]}}`), nil)
	require.Nil(t, rpcErr)
	_, rpcErr = h.send(t, rpcRequest("tasks/get", `{"id":"`+v03Task+`"}`), nil)
	require.Nil(t, rpcErr)

	first := sessionOf(t, ag, 0)
	assert.Equal(t, first, sessionOf(t, ag, 1))
	assert.Equal(t, first, sessionOf(t, ag, 2))

	h.as("u2")
	_, rpcErr = h.send(t, rpcRequest("message/send", `{"message":{"role":"user","contextId":"`+v03Context+`","parts":[]}}`), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.CodeTaskNotFound, rpcErr.Code)
	assert.Equal(t, 3, ag.calls())
	_, rpcErr = h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}]}}`), nil)
	require.NotNil(t, rpcErr, "the answer names u1's context")
	assert.NotEqual(t, first, sessionOf(t, ag, 3))
}

func TestAgentCoreSessionIsNeverTheCallers(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	target := agentCoreTarget()
	target.Headers = map[string]string{"X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": "chosen-by-admin"}
	h := newHostedHarness(t, ag, a2a.Version03, target, agentCoreCard)
	inbound := http.Header{"X-Amzn-Bedrock-Agentcore-Runtime-Session-Id": {"chosen-by-caller"}}
	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[]}}`), inbound)
	require.Nil(t, rpcErr)
	assert.True(t, strings.HasPrefix(sessionOf(t, ag, 0), "tgs-"))
}

func TestAgentCoreRetriesABusySession(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	busy := 1
	ag := newAgent(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if busy > 0 {
			busy--
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32054,"message":"Session operation in progress, please retry"}}`))
			return
		}
		_, _ = w.Write(v03TaskAnswer())
	})
	h := newHostedHarness(t, ag, a2a.Version03, agentCoreTarget(), agentCoreCard)
	result, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[]}}`), nil)
	require.Nil(t, rpcErr)
	assert.Contains(t, string(result), v03Task)
	assert.Equal(t, 2, ag.calls())
	assert.Equal(t, sessionOf(t, ag, 0), sessionOf(t, ag, 1))
}

func TestAgentCoreGivesUpOnABusySessionAfterTwoRetries(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"error":{"code":-32054,"message":"Session operation in progress, please retry"}}`))
	})
	h := newHostedHarness(t, ag, a2a.Version03, agentCoreTarget(), agentCoreCard)
	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[]}}`), nil)
	require.NotNil(t, rpcErr)
	assert.EqualValues(t, -32054, rpcErr.Code)
	assert.Equal(t, 3, ag.calls())
}

func TestAgentCoreErrorStatuses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		header http.Header
		body   string
		code   int64
		reason string
	}{
		{name: "json-rpc error with its status", status: http.StatusNotFound, body: `{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"Task not found"}}`, code: -32001},
		{name: "authorizer refused the user", status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {`Bearer error="invalid_token"`}}, code: a2a.CodeIdentityRequired, reason: a2a.ReasonIdentityRequired},
		{name: "sigv4 refused", status: http.StatusForbidden, body: `{"message":"The security token included in the request is invalid."}`, code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamAuthFailed},
		{name: "throttled", status: http.StatusTooManyRequests, body: `{"jsonrpc":"2.0","id":7,"error":{"code":-32055,"message":"Rate limit exceeded"}}`, code: -32055},
	}
	for _, tc := range cases {
		ag := newAgent(t, func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range tc.header {
				w.Header()[k] = v
			}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		})
		h := newHostedHarness(t, ag, a2a.Version03, agentCoreTarget(), agentCoreCard)
		_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[]}}`), nil)
		require.NotNil(t, rpcErr, tc.name)
		assert.Equal(t, tc.code, rpcErr.Code, tc.name)
		if tc.reason != "" {
			assert.Equal(t, tc.reason, reasonOf(t, rpcErr), tc.name)
		}
	}
}

func TestAgentCoreStreamIsSignedInItsSession(t *testing.T) {
	t.Parallel()
	events := fixtureEvents(t, "v03.stream.response.sse")
	ag, _ := sseAgent(t, events, 0)
	h := newHostedHarness(t, ag, a2a.Version03, agentCoreTarget(), agentCoreCard)
	var got collector
	openStream(t, h.harness, streamRequest(a2a.Version03)).Run(context.Background(), json.RawMessage(`7`), got.emit)

	require.Len(t, got.responses(t), len(events))
	req, _ := ag.request(0)
	assert.Equal(t, "Bearer cloud-token", req.Header.Get("Authorization"))
	owner, ok := h.store.owner(h.harness, a2a.ScopeContext, "ctx-1")
	require.True(t, ok)
	assert.Equal(t, sessionOf(t, ag, 0), owner.UpstreamSession)
}

// The Vertex exchanges below follow the a2a-sdk 0.3 REST handler, which
// parses and writes the protobuf JSON form of the A2A objects. They are not
// recorded from an Agent Engine.
const (
	vertexBase = "https://europe-west1-aiplatform.googleapis.com/v1beta1/projects/acme-agents/locations/europe-west1/reasoningEngines/1234567890/a2a"

	vertexTask = `{"id":"t-1","contextId":"c-1","status":{"state":"TASK_STATE_COMPLETED","message":{"messageId":"m-2","role":"ROLE_AGENT",` +
		`"content":[{"text":"1 USD = 0.92 EUR"}]},"timestamp":"2026-11-11T10:00:00Z"},` +
		`"artifacts":[{"artifactId":"a-1","name":"rate","parts":[{"data":{"data":{"rate":0.92}}},{"file":{"fileWithUri":"gs://b/r.csv","mimeType":"text/csv"}}]}],` +
		`"history":[{"messageId":"m-1","role":"ROLE_USER","content":[{"text":"USD to EUR?"}]}]}`

	rpcVertexTask = `{"kind":"task","id":"t-1","contextId":"c-1","status":{"state":"completed","message":{"kind":"message","messageId":"m-2","role":"agent",` +
		`"parts":[{"kind":"text","text":"1 USD = 0.92 EUR"}]},"timestamp":"2026-11-11T10:00:00Z"},` +
		`"artifacts":[{"artifactId":"a-1","name":"rate","parts":[{"kind":"data","data":{"rate":0.92}},{"kind":"file","file":{"uri":"gs://b/r.csv","mimeType":"text/csv"}}]}],` +
		`"history":[{"kind":"message","messageId":"m-1","role":"user","parts":[{"kind":"text","text":"USD to EUR?"}]}]}`
)

func vertexTarget() *registrydomain.A2ATarget {
	return &registrydomain.A2ATarget{
		Provider:          registrydomain.A2AProviderVertexAgentEngine,
		VertexAgentEngine: &registrydomain.VertexLocator{Project: "acme-agents", Location: "europe-west1", ReasoningEngineID: "1234567890"},
		Auth:              &registrydomain.MCPAuth{Mode: registrydomain.A2AAuthModeCloud},
		CloudAuth:         &registrydomain.A2ACloudAuth{GCP: &registrydomain.A2AGCPAuth{}},
	}
}

func newVertexHarness(t *testing.T, ag *agent) *hostedHarness {
	t.Helper()
	return newHostedHarness(t, ag, a2a.Version03, vertexTarget(), `{"name":"Rates","capabilities":{"streaming":true}}`)
}

func TestVertexSendsMessagesOverREST(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{"task":`+vertexTask+`}`)))
	h := newVertexHarness(t, ag)
	result, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"kind":"message","messageId":"m-1","role":"user",`+
		`"parts":[{"kind":"text","text":"USD to EUR?"},{"kind":"file","file":{"bytes":"aGk=","mimeType":"text/plain","name":"n.txt"}},{"kind":"data","data":{"k":1}}],`+
		`"metadata":{"source":"bot"}},"configuration":{"blocking":true,"historyLength":2,"pushNotificationConfig":{"url":"https://x"}}}`), nil)
	require.Nil(t, rpcErr)

	assert.Equal(t, []string{"POST " + vertexBase + "/v1/message:send"}, h.sent())
	req, body := ag.request(0)
	assert.Equal(t, "Bearer cloud-token", req.Header.Get("Authorization"))
	assert.JSONEq(t, `{"message":{"messageId":"m-1","role":"ROLE_USER","metadata":{"source":"bot"},"content":[{"text":"USD to EUR?"},`+
		`{"file":{"fileWithBytes":"aGk=","mimeType":"text/plain","name":"n.txt"}},{"data":{"data":{"k":1}}}]},`+
		`"configuration":{"blocking":true,"historyLength":2}}`, string(body))
	assert.JSONEq(t, rpcVertexTask, string(result))
	_, owned := h.store.owner(h.harness, a2a.ScopeTask, "t-1")
	assert.True(t, owned)
}

func TestVertexAnswersWithAMessage(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{"message":{"messageId":"m-2","role":"ROLE_AGENT","content":[{"text":"hello"}]}}`)))
	h := newVertexHarness(t, ag)
	result, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"messageId":"m-1","role":"user","parts":[{"kind":"text","text":"hi"}]}}`), nil)
	require.Nil(t, rpcErr)
	assert.JSONEq(t, `{"kind":"message","messageId":"m-2","role":"agent","parts":[{"kind":"text","text":"hello"}]}`, string(result))
}

func TestVertexKeepsFileBytesInBase64(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{"message":{"messageId":"m-2","role":"ROLE_AGENT","content":[{"file":{"fileWithBytes":"aGk=","mimeType":"text/plain"}}]}}`)))
	h := newVertexHarness(t, ag)
	result, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"messageId":"m-1","role":"user","parts":[{"kind":"text","text":"hi"}]}}`), nil)
	require.Nil(t, rpcErr)
	assert.JSONEq(t, `{"kind":"message","messageId":"m-2","role":"agent","parts":[{"kind":"file","file":{"bytes":"aGk=","mimeType":"text/plain"}}]}`, string(result))
}

func TestVertexGetsAndCancelsTasks(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(vertexTask)))
	h := newVertexHarness(t, ag)
	h.store.set(h.harness, a2a.ScopeTask, "t-1", h.owner())

	result, rpcErr := h.send(t, rpcRequest("tasks/get", `{"id":"t-1","historyLength":2}`), nil)
	require.Nil(t, rpcErr)
	assert.JSONEq(t, rpcVertexTask, string(result))
	_, rpcErr = h.send(t, rpcRequest("tasks/cancel", `{"id":"t-1"}`), nil)
	require.Nil(t, rpcErr)

	assert.Equal(t, []string{"GET " + vertexBase + "/v1/tasks/t-1?historyLength=2", "POST " + vertexBase + "/v1/tasks/t-1:cancel"}, h.sent())
	_, body := ag.request(1)
	assert.Empty(t, body)
}

func TestVertexErrorStatuses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		method string
		code   int64
		reason string
	}{
		{status: http.StatusBadRequest, method: "message/send", code: a2a.CodeInvalidParams},
		{status: http.StatusUnauthorized, method: "message/send", code: a2a.CodeIdentityRequired, reason: a2a.ReasonIdentityRequired},
		{status: http.StatusForbidden, method: "message/send", code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamAuthFailed},
		{status: http.StatusNotFound, method: "tasks/get", code: a2a.CodeTaskNotFound},
		{status: http.StatusNotFound, method: "message/send", code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamError},
		{status: http.StatusTooManyRequests, method: "message/send", code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamError},
		{status: http.StatusServiceUnavailable, method: "tasks/get", code: a2a.CodeGatewayFailure, reason: a2a.ReasonUpstreamError},
	}
	for _, tc := range cases {
		ag := newAgent(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"message":"refused"}`))
		})
		h := newVertexHarness(t, ag)
		h.store.set(h.harness, a2a.ScopeTask, "t-1", h.owner())
		params := `{"message":{"messageId":"m-1","role":"user","parts":[]}}`
		if tc.method == "tasks/get" {
			params = `{"id":"t-1"}`
		}
		_, rpcErr := h.send(t, rpcRequest(tc.method, params), nil)
		require.NotNil(t, rpcErr, tc.status)
		assert.Equal(t, tc.code, rpcErr.Code, tc.status)
		if tc.reason != "" {
			assert.Equal(t, tc.reason, reasonOf(t, rpcErr), tc.status)
		}
	}
}

func TestVertexStreamIsRefusedBeforeTheAgent(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{}`)))
	h := newVertexHarness(t, ag)
	for _, body := range [][]byte{streamRequest(a2a.Version03), rpcRequest("tasks/resubscribe", `{"id":"t-1"}`)} {
		_, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, body, nil))
		require.NotNil(t, rpcErr)
		assert.Equal(t, a2a.UnsupportedOperation(a2a.Version03), rpcErr)
	}
	assert.Zero(t, ag.calls())
}

func TestCloudSignKeyFollowsTheResolvedSecret(t *testing.T) {
	t.Parallel()
	signer := &cloudSigner{}
	creds := a2a.NewCredentials(nil, nil, signer, false)
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), UpdatedAt: time.Unix(10, 0), A2ATarget: foundryTarget()}
	runtime := *reg
	runtime.BindSecrets(reg, "digest-1")
	req := httptest.NewRequest(http.MethodPost, "https://acme.services.ai.azure.com/a2a", nil)
	require.NoError(t, creds.Sign(context.Background(), &runtime, req))
	rotated := *reg
	rotated.BindSecrets(reg, "digest-2")
	require.NoError(t, creds.Sign(context.Background(), &rotated, req))

	require.Len(t, signer.keys, 2)
	assert.NotEqual(t, signer.keys[0].Version, signer.keys[1].Version, "a rotated secret must not reuse the cached cloud credential")
	assert.Contains(t, signer.keys[0].Version, "digest-1")
}
