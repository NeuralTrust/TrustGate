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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const testTimeout = 2 * time.Second

func openAIRequestBody() []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"be safe"},{"role":"user","content":"hello world"}]}`)
}

func openAIResponseBody() []byte {
	return []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"the answer"},"finish_reason":"stop"}]}`)
}

func requestContext() *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Provider:       "openai",
		SourceFormat:   "openai",
		GatewayID:      "gw-test",
		SessionID:      "sess-123",
		ConsumerID:     "consumer-9",
		RequestedModel: "gpt-4o-mini",
		Body:           openAIRequestBody(),
	}
}

func settings(inspect string) map[string]any {
	s := map[string]any{"collector_id": testCollectorID}
	if inspect != "" {
		s["inspect"] = inspect
	}
	return s
}

type fakeGuard struct {
	mu          sync.Mutex
	hits        int
	lastBody    GuardRequest
	lastMethod  string
	lastPath    string
	lastAuth    string
	lastCT      string
	directions  []string
	status      int
	response    GuardResponse
	responseFor map[string]GuardResponse
}

func (f *fakeGuard) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "test-token", TokenType: "Bearer", ExpiresIn: 3600})
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		f.lastMethod = r.Method
		f.lastPath = r.URL.Path
		f.lastAuth = r.Header.Get("Authorization")
		f.lastCT = r.Header.Get("Content-Type")
		if r.URL.Path != guardPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body GuardRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastBody = body
		f.directions = append(f.directions, body.Direction)
		status := f.status
		if status == 0 {
			status = http.StatusOK
		}
		resp := f.response
		if r, ok := f.responseFor[body.Direction]; ok {
			resp = r
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (f *fakeGuard) http() (method, path, auth, contentType string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastMethod, f.lastPath, f.lastAuth, f.lastCT
}

func (f *fakeGuard) seenDirections() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.directions))
	copy(out, f.directions)
	return out
}

func (f *fakeGuard) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

func (f *fakeGuard) captured() GuardRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastBody
}

func newServer(t *testing.T, f *fakeGuard) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

func execInput(stage policy.Stage, mode policy.Mode, set map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Mode:     mode,
		Config:   policy.PluginConfig{Settings: set},
		Request:  req,
		Response: resp,
	}
}

func TestExecutePreRequestBlockReturns403(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{
		Status:    statusBlock,
		Findings:  []GuardFinding{{DetectionType: "prompt_injection", Action: "block"}},
		TraceID:   "trace-1",
		RequestID: "req-1",
	}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on block, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusForbidden)
	}
	if pe.Type != typeBlocked {
		t.Fatalf("type = %q, want %q", pe.Type, typeBlocked)
	}
	if len(pe.Body) == 0 {
		t.Fatalf("expected non-empty block body")
	}
	got := f.captured()
	if got.Direction != directionInput {
		t.Fatalf("direction = %q, want %q", got.Direction, directionInput)
	}
	if got.ConsumerID != "consumer-9" {
		t.Fatalf("consumer_id = %q, want consumer-9", got.ConsumerID)
	}
	if got.SessionID != "sess-123" {
		t.Fatalf("session_id = %q, want sess-123", got.SessionID)
	}
	if got.Protocol != protocolLLM {
		t.Fatalf("protocol = %q, want %q", got.Protocol, protocolLLM)
	}
	if got.Attributes.Model.Name != "gpt-4o-mini" || got.Attributes.Model.Provider != "openai" {
		t.Fatalf("model = %+v, want gpt-4o-mini/openai", got.Attributes.Model)
	}
	if got.Input.Input != "be safe\nhello world" {
		t.Fatalf("input = %q, want %q", got.Input.Input, "be safe\nhello world")
	}
}

func TestExecutePreResponseBlockReturns403(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock, TraceID: "trace-2"}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	resp := &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseBody()}
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), requestContext(), resp)
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on block, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusForbidden)
	}
	got := f.captured()
	if got.Direction != directionOutput {
		t.Fatalf("direction = %q, want %q", got.Direction, directionOutput)
	}
	if got.Input.Input != "the answer" {
		t.Fatalf("input = %q, want %q", got.Input.Input, "the answer")
	}
}

func TestExecuteObserveModeOnBlockPassesThrough(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock, TraceID: "trace-3"}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, settings(""), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("observe mode must not error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through in observe mode, got %+v", res)
	}
	if f.count() != 1 {
		t.Fatalf("expected guard called once, got %d", f.count())
	}
}

func TestExecuteAllowStatusesPassThrough(t *testing.T) {
	t.Parallel()

	for _, status := range []string{"report", "transform", ""} {
		status := status
		t.Run("status_"+status, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: status}}
			srv := newServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
			res, err := p.Execute(context.Background(), in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
				t.Fatalf("expected pass-through, got %+v", res)
			}
		})
	}
}

func TestExecuteStreamingResponsePassThrough(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	resp := &infracontext.ResponseContext{StatusCode: 200, Streaming: true, Body: openAIResponseBody()}
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), requestContext(), resp)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through, got %+v", res)
	}
	if f.count() != 0 {
		t.Fatalf("expected guard not called for streaming, got %d hits", f.count())
	}
}

func TestExecuteEmptyBaseURLPassThrough(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	p := New(adapter.NewRegistry(), "", testTimeout, "test-client", "test-secret", nil)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through, got %+v", res)
	}
	if f.count() != 0 {
		t.Fatalf("expected guard not called with empty base url, got %d hits", f.count())
	}
}

func TestExecuteTransportErrorFailsOpen(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	srv := httptest.NewServer(f.handler())
	addr := srv.URL
	srv.Close()

	p := New(adapter.NewRegistry(), addr, testTimeout, "test-client", "test-secret", nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected fail-open pass, got error %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through on transport error, got %+v", res)
	}
}

func TestExecuteMissingGatewayIDFailsOpenWithoutCall(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	req := requestContext()
	req.GatewayID = ""
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected fail-open pass, got error %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through on missing gateway id, got %+v", res)
	}
	if f.count() != 0 {
		t.Fatalf("expected no guard call when gateway id missing, got %d hits", f.count())
	}
}

func TestExecuteStageNotSelectedPassThrough(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(inspectResponse), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through, got %+v", res)
	}
	if f.count() != 0 {
		t.Fatalf("expected guard not called when stage not selected, got %d hits", f.count())
	}
}

func TestExecuteProtocolFromConsumerType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		consumerType string
		want         string
	}{
		{name: "llm consumer", consumerType: "LLM", want: protocolLLM},
		{name: "mcp consumer", consumerType: "MCP", want: protocolMCP},
		{name: "a2a consumer", consumerType: "A2A", want: protocolA2A},
		{name: "unset consumer", consumerType: "", want: protocolLLM},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: "allowed"}}
			srv := newServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

			req := requestContext()
			req.ConsumerType = tc.consumerType
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil)
			if _, err := p.Execute(context.Background(), in); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := f.captured().Protocol; got != tc.want {
				t.Fatalf("protocol = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestProtocolFor(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"LLM":      protocolLLM,
		"llm":      protocolLLM,
		"MCP":      protocolMCP,
		"  mcp  ":  protocolMCP,
		"A2A":      protocolA2A,
		"":         protocolLLM,
		"whatever": protocolLLM,
	}
	for raw, want := range cases {
		if got := protocolFor(raw); got != want {
			t.Fatalf("protocolFor(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestExecuteForwardsFullGuardRequest(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: "allowed"}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	req := requestContext()
	req.ConsumerType = "MCP"
	req.ConsumerID = "consumer-real-42"
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil)
	if _, err := p.Execute(context.Background(), in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	method, path, auth, ct := f.http()
	if method != http.MethodPost {
		t.Fatalf("method = %q, want POST", method)
	}
	if path != guardPath {
		t.Fatalf("path = %q, want %q", path, guardPath)
	}
	if got := f.captured().GatewayID; got != "gw-test" {
		t.Fatalf("gateway_id = %q, want gw-test", got)
	}
	if auth != "Bearer test-token" {
		t.Fatalf("authorization = %q, want %q", auth, "Bearer test-token")
	}
	if ct != contentTypeJSON {
		t.Fatalf("content-type = %q, want %q", ct, contentTypeJSON)
	}

	got := f.captured()
	if got.Direction != directionInput {
		t.Fatalf("direction = %q, want %q", got.Direction, directionInput)
	}
	if got.Protocol != protocolMCP {
		t.Fatalf("protocol = %q, want %q", got.Protocol, protocolMCP)
	}
	if got.SessionID != "sess-123" {
		t.Fatalf("session_id = %q, want sess-123", got.SessionID)
	}
	if got.ConsumerID != "consumer-real-42" {
		t.Fatalf("consumer_id = %q, want consumer-real-42", got.ConsumerID)
	}
	if got.Input.Input != "be safe\nhello world" {
		t.Fatalf("input = %q, want %q", got.Input.Input, "be safe\nhello world")
	}
	if got.Attributes.ContentType != contentTypeJSON {
		t.Fatalf("attributes.content_type = %q, want %q", got.Attributes.ContentType, contentTypeJSON)
	}
	if got.Attributes.Model.Name != "gpt-4o-mini" || got.Attributes.Model.Provider != "openai" {
		t.Fatalf("model = %+v, want gpt-4o-mini/openai", got.Attributes.Model)
	}
}

func TestExecuteConsumerIDComesFromRequestNotSettings(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: "allowed"}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	req := requestContext()
	req.ConsumerID = "from-request"
	set := settings("")
	set["consumer_id"] = "from-settings-should-be-ignored"
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, req, nil)
	if _, err := p.Execute(context.Background(), in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := f.captured().ConsumerID; got != "from-request" {
		t.Fatalf("consumer_id = %q, want from-request", got)
	}
}

func TestExecuteInspectModeDirections(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		inspect    string
		directions []string
	}{
		{name: "request only", inspect: inspectRequest, directions: []string{directionInput}},
		{name: "response only", inspect: inspectResponse, directions: []string{directionOutput}},
		{name: "request_response", inspect: inspectRequestResponse, directions: []string{directionInput, directionOutput}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: "allowed"}}
			srv := newServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

			resp := &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseBody()}
			for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
				in := execInput(stage, policy.ModeEnforce, settings(tc.inspect), requestContext(), resp)
				if _, err := p.Execute(context.Background(), in); err != nil {
					t.Fatalf("stage %s: unexpected error: %v", stage, err)
				}
			}

			got := f.seenDirections()
			if len(got) != len(tc.directions) {
				t.Fatalf("directions = %v, want %v", got, tc.directions)
			}
			for i, d := range tc.directions {
				if got[i] != d {
					t.Fatalf("direction[%d] = %q, want %q", i, got[i], d)
				}
			}
		})
	}
}

func TestExecuteBaseURLOverrideFromSettings(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: "allowed"}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), "https://unreachable.invalid", testTimeout, "test-client", "test-secret", nil)

	set := settings("")
	set["base_url"] = srv.URL
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil)
	if _, err := p.Execute(context.Background(), in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.count() != 1 {
		t.Fatalf("expected guard called once via settings base_url, got %d", f.count())
	}
}

func TestExecuteRetriesOnceOn401(t *testing.T) {
	t.Parallel()

	var guardHits int32
	var tokenHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case tokenPath:
			atomic.AddInt32(&tokenHits, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600})
		case guardPath:
			if atomic.AddInt32(&guardHits, 1) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(GuardResponse{Status: "allowed"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected success after 401 retry, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through after retry, got %+v", res)
	}
	if got := atomic.LoadInt32(&guardHits); got != 2 {
		t.Fatalf("guard hits = %d, want 2 (original + retry)", got)
	}
	if got := atomic.LoadInt32(&tokenHits); got != 2 {
		t.Fatalf("token hits = %d, want 2 (initial + refresh after 401)", got)
	}
}

func TestExecuteBlocksOnlyOnFlaggedLeg(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{responseFor: map[string]GuardResponse{
		directionInput:  {Status: "allowed"},
		directionOutput: {Status: statusBlock, TraceID: "trace-out"},
	}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, "test-client", "test-secret", nil)

	reqIn := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
	if _, err := p.Execute(context.Background(), reqIn); err != nil {
		t.Fatalf("pre_request leg must pass (allowed), got %v", err)
	}

	resp := &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseBody()}
	respIn := execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), requestContext(), resp)
	res, err := p.Execute(context.Background(), respIn)
	if res != nil {
		t.Fatalf("expected nil result on response block, got %+v", res)
	}
	if _, ok := appplugins.AsPluginError(err); !ok {
		t.Fatalf("expected *PluginError on response block, got %v", err)
	}
}
