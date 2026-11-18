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

package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/trustguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// TestForward_StreamedTrustGuardBlockCarriesTheBufferedFields: a TrustGuard
// block on the head of a stream is not the buffered leg's 403. The stream opens
// and ends on the content-filter terminator and blocked event, and that event
// carries the policy fields the buffered body names the finding with, so an
// integrator correlates a block the same way on both legs.
func TestForward_StreamedTrustGuardBlockCarriesTheBufferedFields(t *testing.T) {
	t.Parallel()

	block := trustguard.GuardResponse{
		Status:    "block",
		TraceID:   "trace-canary",
		RequestID: "req-canary",
		Findings: []trustguard.GuardFinding{{
			Source: &trustguard.GuardFindingSource{
				Kind:         "detector",
				Plugin:       "data_loss_prevention",
				DetectorName: "probe-canary-output",
			},
			Signal:   &trustguard.GuardFindingSignal{Type: "secret", Confidence: 0.99},
			Outcome:  &trustguard.GuardFindingOutcome{Action: "block"},
			Evidence: map[string]any{"policy_id": "probe-tg-stream-toolcall"},
		}},
	}
	blockRaw, err := json.Marshal(block)
	require.NoError(t, err)
	allowRaw, err := json.Marshal(trustguard.GuardResponse{Status: "allow"})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
		case "/v1/evaluate":
			var req struct {
				Direction string `json:"direction"`
			}
			if decErr := json.NewDecoder(r.Body).Decode(&req); decErr != nil {
				http.Error(w, decErr.Error(), http.StatusBadRequest)
				return
			}
			if req.Direction == "output" {
				_, _ = w.Write(blockRaw)
				return
			}
			_, _ = w.Write(allowRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	plugin := trustguard.New(adapter.NewRegistry(), srv.URL, 5*time.Second, "test-client", "test-secret", newTestLogger())
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "trustguard",
		Slug:     trustguard.PluginName,
		Enabled:  true,
		Priority: 1,
		Mode:     policy.ModeEnforce,
		Settings: map[string]any{
			"collector_id": "11111111-1111-4111-8111-111111111111",
			"direction":    "request_response",
		},
	}}
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(plugin))
	rc.PolicyPlan = appplugins.NewStagePlan(reg, rc.Policies, newTestLogger())

	bufferedBody := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4.1-nano","choices":[{"index":0,"message":{"role":"assistant","content":"the secret"},"finish_reason":"stop"}]}`)
	lines := [][]byte{
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"the secret"}}]}`),
		{},
		[]byte("data: [DONE]"),
		{},
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: http.StatusOK, Body: bufferedBody}, nil).
		Once()
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: http.StatusOK, Stream: sseLinesStream(lines)}, nil).
		Once()

	fwd := forwarderWithPlugin(t, invoker, plugin, appproxy.WithStreamCodec(adapter.NewRegistry()))
	buffered, err := fwd.Forward(t.Context(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   trustGuardChatRequest(false),
	})
	require.NoError(t, err)
	streamed, err := fwd.Forward(t.Context(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   trustGuardChatRequest(true),
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusForbidden, buffered.StatusCode)
	assert.Equal(t, []string{appplugins.BlockDirectionOutput}, buffered.Headers[appplugins.BlockDirectionHeader])
	var want map[string]any
	require.NoError(t, json.Unmarshal(buffered.Body, &want))
	assert.Equal(t, "trustguard_blocked", want["type"])

	require.Equal(t, http.StatusOK, streamed.StatusCode)
	assert.Equal(t, []string{appplugins.BlockDirectionOutput}, streamed.Headers[appplugins.BlockDirectionHeader],
		"the head's headers were still unsent, so the block's direction rides the 200")
	got := collectStream(t, streamed.Stream)
	require.Equal(t, "data: [DONE]", got[len(got)-2])
	var event struct {
		Error map[string]any `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(got[len(got)-4], "data: ")), &event))
	assert.NotContains(t, strings.Join(got, "\n"), "the secret", "none of the text reaches the client")
	assert.Contains(t, got[len(got)-6], `"finish_reason":"content_filter"`)

	assert.Equal(t, "content_filter", event.Error["type"], "the dialect's type is the one every cut carries")
	assert.Equal(t, want["message"], event.Error["message"])
	for _, field := range []string{"direction", "reason", "plugin", "detector_name", "trace_id", "request_id"} {
		assert.Equal(t, want[field], event.Error[field], field)
	}
	assert.Equal(t, "probe-canary-output", event.Error["detector_name"])
	assert.Equal(t, "trace-canary", event.Error["trace_id"])
}

func TestForward_StreamedTrustGuardRateLimitMatchesBuffered(t *testing.T) {
	t.Parallel()
	forwardTrustGuardRateLimit(t, policy.ModeEnforce)
}

func forwardTrustGuardRateLimit(t *testing.T, mode policy.Mode) {
	t.Helper()

	// Not the flat plan shape (reason is not burst or quota), so the forwarder
	// leaves the body as the plugin hands it over on both legs: TrustGuard's,
	// marked with its source.
	raw := []byte(`{"error":"rate limit exceeded","reason":"collector"}`)
	want := `{"error":"rate limit exceeded","reason":"collector","source":"trustguard"}`
	allowRaw, err := json.Marshal(trustguard.GuardResponse{Status: "allow"})
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/token":
			_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
		case "/v1/evaluate":
			var req struct {
				Direction string `json:"direction"`
			}
			if decErr := json.NewDecoder(r.Body).Decode(&req); decErr != nil {
				http.Error(w, decErr.Error(), http.StatusBadRequest)
				return
			}
			if req.Direction == "output" {
				w.Header().Set("Retry-After", "9")
				w.Header().Set("X-RateLimit-Limit", "60")
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reason", "collector")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write(raw)
				return
			}
			_, _ = w.Write(allowRaw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	plugin := trustguard.New(adapter.NewRegistry(), srv.URL, 5*time.Second, "test-client", "test-secret", newTestLogger())
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	rc.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "trustguard",
		Slug:     trustguard.PluginName,
		Enabled:  true,
		Priority: 1,
		Mode:     mode,
		Settings: map[string]any{
			"collector_id": "11111111-1111-4111-8111-111111111111",
			"direction":    "request_response",
		},
	}}
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(plugin))
	rc.PolicyPlan = appplugins.NewStagePlan(reg, rc.Policies, newTestLogger())

	bufferedBody := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4.1-nano","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`)
	lines := [][]byte{
		[]byte(`data: {"id":"c","choices":[{"index":0,"delta":{"content":"hello"}}]}`),
		{},
		[]byte("data: [DONE]"),
		{},
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: http.StatusOK, Body: bufferedBody}, nil).
		Once()
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: http.StatusOK, Stream: sseLinesStream(lines)}, nil).
		Once()

	fwd := forwarderWithPlugin(t, invoker, plugin, appproxy.WithStreamCodec(adapter.NewRegistry()))
	buffered, err := fwd.Forward(t.Context(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   trustGuardChatRequest(false),
	})
	require.NoError(t, err)
	streamed, err := fwd.Forward(t.Context(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   trustGuardChatRequest(true),
	})
	require.NoError(t, err)

	require.Equal(t, http.StatusTooManyRequests, buffered.StatusCode)
	require.Equal(t, http.StatusTooManyRequests, streamed.StatusCode)
	require.Nil(t, streamed.Stream)
	require.JSONEq(t, want, string(buffered.Body))
	require.JSONEq(t, string(buffered.Body), string(streamed.Body))
	for _, name := range []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reason"} {
		assert.Equal(t, buffered.Headers[name], streamed.Headers[name], name)
	}
	assert.Equal(t, []string{"9"}, streamed.Headers["Retry-After"])
	assert.Equal(t, []string{"60"}, streamed.Headers["X-RateLimit-Limit"])
	assert.Equal(t, []string{"0"}, streamed.Headers["X-RateLimit-Remaining"])
	assert.Equal(t, []string{"collector"}, streamed.Headers["X-RateLimit-Reason"])
	assert.Empty(t, streamed.Headers[appplugins.BlockDirectionHeader])
	assert.Empty(t, buffered.Headers[appplugins.BlockDirectionHeader])
	assert.Equal(t, []string{"application/json"}, streamed.Headers["Content-Type"])
	assert.Equal(t, []string{"application/json"}, buffered.Headers["Content-Type"])
}

func trustGuardChatRequest(stream bool) *infracontext.RequestContext {
	body := `{"model":"gpt-4.1-nano","messages":[{"role":"user","content":"hello"}]}`
	if stream {
		body = `{"model":"gpt-4.1-nano","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	}
	return &infracontext.RequestContext{
		SourceFormat:    "openai",
		ProxyCapability: "chat",
		Body:            []byte(body),
	}
}
