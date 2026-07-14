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

package regexreplace

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	openAIProvider    = "openai"
	anthropicProvider = "anthropic"
)

func maskRule(pattern, replacement string) map[string]any {
	return map[string]any{"pattern": pattern, "replacement": replacement}
}

func settings(target string, rules ...map[string]any) map[string]any {
	return map[string]any{"target": target, "rules": rules}
}

func reqCtx(provider, source string, body []byte) *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: provider, SourceFormat: source, Body: body}
}

func respCtx(body []byte, streaming bool) *infracontext.ResponseContext {
	return &infracontext.ResponseContext{Body: body, Streaming: streaming}
}

func newEvent() (*metrics.EventContext, *trace.Span) {
	tr := trace.New("", trace.Metadata{})
	span := tr.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func execInput(stage policy.Stage, mode policy.Mode, set map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext, event *metrics.EventContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Mode:     mode,
		Config:   policy.PluginConfig{Settings: set},
		Request:  req,
		Response: resp,
		Event:    event,
	}
}

func openAIRequest(system, user string) []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"` + system + `"},{"role":"user","content":"` + user + `"}]}`)
}

func anthropicRequest(system, user string) []byte {
	return []byte(`{"model":"claude-3","system":"` + system + `","messages":[{"role":"user","content":"` + user + `"}],"max_tokens":100}`)
}

func openAIResponse(content string) []byte {
	return []byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"` + content + `"},"finish_reason":"stop"}]}`)
}

func anthropicResponse(content string) []byte {
	return []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"` + content + `"}],"stop_reason":"end_turn","usage":{"input_tokens":30,"output_tokens":15}}`)
}

func assertPassThrough(t *testing.T, res *appplugins.Result, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream || res.Body != nil || res.RequestBody != nil {
		t.Fatalf("expected pass-through, got %+v", res)
	}
}

func extras(t *testing.T, span *trace.Span) *Data {
	t.Helper()
	if span.Plugin == nil {
		t.Fatal("expected plugin span attrs")
	}
	data, ok := span.Plugin.Extras.(*Data)
	if !ok {
		t.Fatalf("expected *Data extras, got %T", span.Plugin.Extras)
	}
	return data
}

func TestDescriptor(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	if p.Name() != PluginName {
		t.Fatalf("Name = %q, want %q", p.Name(), PluginName)
	}
	if len(p.MandatoryStages()) != 0 {
		t.Fatalf("MandatoryStages = %v, want empty", p.MandatoryStages())
	}
	stages := p.SupportedStages()
	if len(stages) != 2 || stages[0] != policy.StagePreRequest || stages[1] != policy.StagePreResponse {
		t.Fatalf("SupportedStages = %v", stages)
	}
	modes := p.SupportedModes()
	if len(modes) != 2 || modes[0] != policy.ModeEnforce || modes[1] != policy.ModeObserve {
		t.Fatalf("SupportedModes = %v", modes)
	}
	protocols := p.SupportedProtocols()
	if len(protocols) != 1 || protocols[0] != appplugins.ProtocolLLM {
		t.Fatalf("SupportedProtocols = %v", protocols)
	}
	if !p.MutatesRequestBody() || !p.MutatesResponseBody() {
		t.Fatal("MutatesRequestBody and MutatesResponseBody must be true")
	}
	if p.MutatesMetadata() {
		t.Fatal("MutatesMetadata must be false")
	}
}

func TestValidateConfigRejectsInvalid(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	if err := p.ValidateConfig(settings("both", maskRule("a", "b"))); err == nil {
		t.Fatal("expected error for invalid target")
	}
	if err := p.ValidateConfig(settings(targetRequest, maskRule("a", "b"))); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestStageTargetNoOp(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	tests := []struct {
		name  string
		stage policy.Stage
		set   map[string]any
		req   *infracontext.RequestContext
		resp  *infracontext.ResponseContext
	}{
		{
			name:  "request target on pre_response",
			stage: policy.StagePreResponse,
			set:   settings(targetRequest, maskRule("world", "earth")),
			req:   reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "hello world")),
			resp:  respCtx(openAIResponse("hello world"), false),
		},
		{
			name:  "response target on pre_request",
			stage: policy.StagePreRequest,
			set:   settings(targetResponse, maskRule("world", "earth")),
			req:   reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "hello world")),
			resp:  nil,
		},
		{
			name:  "unsupported stage",
			stage: policy.StagePostResponse,
			set:   settings(targetRequest, maskRule("world", "earth")),
			req:   reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "hello world")),
			resp:  respCtx(openAIResponse("hello world"), false),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event, span := newEvent()
			in := execInput(tt.stage, policy.ModeEnforce, tt.set, tt.req, tt.resp, event)
			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			if span.Plugin != nil && span.Plugin.Extras != nil {
				t.Fatalf("expected no telemetry on stage/target no-op, got %+v", span.Plugin.Extras)
			}
		})
	}
}

func TestRequestLegRewrite(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, openAIProvider, openAIRequest("keep secret", "my secret code")), nil, event)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream || len(res.RequestBody) == 0 || res.Body != nil {
		t.Fatalf("expected request rewrite result, got %+v", res)
	}
	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("decode rewritten request: %v", err)
	}
	if creq.System != "keep [REDACTED]" {
		t.Fatalf("system = %q, want %q", creq.System, "keep [REDACTED]")
	}
	if got := creq.Messages[len(creq.Messages)-1].Content; got != "my [REDACTED] code" {
		t.Fatalf("user content = %q, want %q", got, "my [REDACTED] code")
	}
	if d := extras(t, span); d.Decision != decisionRewritten || !d.Changed {
		t.Fatalf("extras = %+v, want rewritten+changed", d)
	}
}

func TestResponseLegRewrite(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetResponse, maskRule("answer", "solution"))
	event, span := newEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, set, reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "question")), respCtx(openAIResponse("the answer"), false), event)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || !res.StopUpstream || len(res.Body) == 0 || res.RequestBody != nil {
		t.Fatalf("expected response rewrite with StopUpstream, got %+v", res)
	}
	cresp, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("decode rewritten response: %v", err)
	}
	if cresp.Content != "the solution" {
		t.Fatalf("content = %q, want %q", cresp.Content, "the solution")
	}
	if d := extras(t, span); d.Decision != decisionRewritten {
		t.Fatalf("decision = %q, want %q", d.Decision, decisionRewritten)
	}
}

func TestObserveModeDoesNotMutate(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	t.Run("request", func(t *testing.T) {
		t.Parallel()
		set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
		event, span := newEvent()
		in := execInput(policy.StagePreRequest, policy.ModeObserve, set, reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "my secret")), nil, event)
		res, err := p.Execute(context.Background(), in)
		assertPassThrough(t, res, err)
		if d := extras(t, span); d.Decision != decisionObserved || !d.Changed {
			t.Fatalf("extras = %+v, want observed+changed", d)
		}
	})

	t.Run("response", func(t *testing.T) {
		t.Parallel()
		set := settings(targetResponse, maskRule("answer", "solution"))
		event, span := newEvent()
		in := execInput(policy.StagePreResponse, policy.ModeObserve, set, reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), false), event)
		res, err := p.Execute(context.Background(), in)
		assertPassThrough(t, res, err)
		if d := extras(t, span); d.Decision != decisionObserved {
			t.Fatalf("decision = %q, want %q", d.Decision, decisionObserved)
		}
	})
}

func TestStreamingResponsePassThrough(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetResponse, maskRule("answer", "solution"))
	event, span := newEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, set, reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), true), event)

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	if span.Plugin != nil && span.Plugin.Extras != nil {
		t.Fatalf("expected no telemetry on streaming pass-through, got %+v", span.Plugin.Extras)
	}
}

func TestNoMatchNoMutation(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetRequest, maskRule("absent", "x"))
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "hello world")), nil, event)

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
	d := extras(t, span)
	if d.Decision != decisionNoMatch || d.Changed {
		t.Fatalf("extras = %+v, want no_match and changed=false", d)
	}
}

func TestCrossProviderRewrite(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	tests := []struct {
		name     string
		provider string
		format   adapter.Format
		body     []byte
	}{
		{"openai", openAIProvider, adapter.FormatOpenAI, openAIRequest("keep secret", "my secret")},
		{"anthropic", anthropicProvider, adapter.FormatAnthropic, anthropicRequest("keep secret", "my secret")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
			event, _ := newEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(tt.provider, tt.provider, tt.body), nil, event)
			res, err := p.Execute(context.Background(), in)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if res == nil || len(res.RequestBody) == 0 {
				t.Fatalf("expected rewritten request body, got %+v", res)
			}
			creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, tt.format)
			if err != nil {
				t.Fatalf("decode rewritten request: %v", err)
			}
			if creq.System != "keep [REDACTED]" {
				t.Fatalf("system = %q, want %q", creq.System, "keep [REDACTED]")
			}
			if got := creq.Messages[len(creq.Messages)-1].Content; got != "my [REDACTED]" {
				t.Fatalf("user content = %q, want %q", got, "my [REDACTED]")
			}
		})
	}
}

func TestCrossProviderResponseRewrite(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetResponse, maskRule("answer", "solution"))
	event, _ := newEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, set, reqCtx(anthropicProvider, anthropicProvider, anthropicRequest("be safe", "q")), respCtx(anthropicResponse("the answer"), false), event)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || !res.StopUpstream || len(res.Body) == 0 {
		t.Fatalf("expected anthropic response rewrite, got %+v", res)
	}
	cresp, err := adapter.NewRegistry().DecodeResponseFor(res.Body, adapter.FormatAnthropic)
	if err != nil {
		t.Fatalf("decode rewritten response: %v", err)
	}
	if cresp.Content != "the solution" {
		t.Fatalf("content = %q, want %q", cresp.Content, "the solution")
	}
}

func TestExecuteGuardPassThroughs(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	tests := []struct {
		name  string
		stage policy.Stage
		set   map[string]any
		req   *infracontext.RequestContext
		resp  *infracontext.ResponseContext
	}{
		{"nil request", policy.StagePreRequest, settings(targetRequest, maskRule("a", "b")), nil, nil},
		{"empty request body", policy.StagePreRequest, settings(targetRequest, maskRule("a", "b")), reqCtx(openAIProvider, openAIProvider, nil), nil},
		{"empty provider request", policy.StagePreRequest, settings(targetRequest, maskRule("a", "b")), reqCtx("", "", openAIRequest("s", "u")), nil},
		{"nil response", policy.StagePreResponse, settings(targetResponse, maskRule("a", "b")), reqCtx(openAIProvider, openAIProvider, openAIRequest("s", "u")), nil},
		{"empty response body", policy.StagePreResponse, settings(targetResponse, maskRule("a", "b")), reqCtx(openAIProvider, openAIProvider, openAIRequest("s", "u")), respCtx(nil, false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event, _ := newEvent()
			in := execInput(tt.stage, policy.ModeEnforce, tt.set, tt.req, tt.resp, event)
			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
		})
	}
}

func TestRequestRewritePreservesNonTextFields(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	body := []byte(`{"model":"gpt-4o","temperature":0.7,"tools":[{"type":"function","function":{"name":"get_weather","description":"d","parameters":{"type":"object"}}}],"messages":[{"role":"user","content":"my secret code"}]}`)
	set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
	event, _ := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, openAIProvider, body), nil, event)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res == nil || len(res.RequestBody) == 0 {
		t.Fatalf("expected rewritten request body, got %+v", res)
	}
	for _, want := range []string{"gpt-4o", "temperature", "get_weather", "[REDACTED]"} {
		if !bytes.Contains(res.RequestBody, []byte(want)) {
			t.Fatalf("rewritten body missing %q: %s", want, res.RequestBody)
		}
	}
	if bytes.Contains(res.RequestBody, []byte("my secret code")) {
		t.Fatalf("rewritten body still contains original secret: %s", res.RequestBody)
	}
}

func TestExecuteDoesNotMutateInputBodyInPlace(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)

	t.Run("request", func(t *testing.T) {
		t.Parallel()
		original := openAIRequest("keep secret", "my secret code")
		snapshot := append([]byte(nil), original...)
		event, _ := newEvent()
		req := reqCtx(openAIProvider, openAIProvider, original)
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(targetRequest, maskRule("secret", "[REDACTED]")), req, nil, event)
		if _, err := p.Execute(context.Background(), in); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !bytes.Equal(req.Body, snapshot) {
			t.Fatalf("request body mutated in place: %s", req.Body)
		}
	})

	t.Run("response", func(t *testing.T) {
		t.Parallel()
		original := openAIResponse("the answer")
		snapshot := append([]byte(nil), original...)
		event, _ := newEvent()
		resp := respCtx(original, false)
		in := execInput(policy.StagePreResponse, policy.ModeEnforce, settings(targetResponse, maskRule("answer", "solution")), reqCtx(openAIProvider, openAIProvider, openAIRequest("s", "u")), resp, event)
		if _, err := p.Execute(context.Background(), in); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !bytes.Equal(resp.Body, snapshot) {
			t.Fatalf("response body mutated in place: %s", resp.Body)
		}
	})
}

func TestExecuteInvalidConfigErrors(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings("both", maskRule("a", "b")), reqCtx(openAIProvider, openAIProvider, openAIRequest("s", "u")), nil, nil)
	res, err := p.Execute(context.Background(), in)
	if err == nil {
		t.Fatal("expected error on invalid config")
	}
	if res != nil {
		t.Fatalf("expected nil result on invalid config, got %+v", res)
	}
}
