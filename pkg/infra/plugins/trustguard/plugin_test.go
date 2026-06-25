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
		SessionID:      "sess-123",
		ConsumerID:     "consumer-9",
		RequestedModel: "gpt-4o-mini",
		Body:           openAIRequestBody(),
	}
}

func settings(inspect string) map[string]any {
	s := map[string]any{
		"api_key": "secret-key",
	}
	if inspect != "" {
		s["inspect"] = inspect
	}
	return s
}

type fakeGuard struct {
	mu       sync.Mutex
	hits     int
	lastBody GuardRequest
	status   int
	response GuardResponse
}

func (f *fakeGuard) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		if r.URL.Path != guardPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body GuardRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastBody = body
		status := f.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(f.response)
	}
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
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
			p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
	p := New(adapter.NewRegistry(), "", testTimeout, nil)

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

	p := New(adapter.NewRegistry(), addr, testTimeout, nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected fail-open pass, got error %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through on transport error, got %+v", res)
	}
}

func TestExecuteStageNotSelectedPassThrough(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
			p := New(adapter.NewRegistry(), srv.URL, testTimeout, nil)

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
