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

package tool_call_validation

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func openAIRequestWithTools() []byte {
	return []byte(`{
		"model": "gpt-4o",
		"messages": [{"role": "user", "content": "send an email"}],
		"tools": [{"type": "function", "function": {"name": "send_email", "parameters": {"type": "object", "properties": {"to": {"type": "string"}}, "required": ["to"]}}}]
	}`)
}

func openAIResponseWithToolCall(name, args string) []byte {
	call := fmt.Sprintf(`{"id":"call_1","type":"function","function":{"name":%q,"arguments":%q}}`, name, args)
	return []byte(fmt.Sprintf(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[%s]},"finish_reason":"tool_calls"}]}`, call))
}

func openAIResponseNoToolCalls() []byte {
	return []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`)
}

func allowedListSettings() map[string]any {
	return map[string]any{
		"rules": []any{
			map[string]any{"validator": "not_in_allowed_list", "behavior": "reject_response"},
		},
	}
}

func newExecInput(settings map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    policy.StagePreResponse,
		Mode:     policy.ModeEnforce,
		Config:   policy.PluginConfig{Settings: settings},
		Request:  req,
		Response: resp,
	}
}

func openAIRequest() *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: "openai", SourceFormat: "openai", Body: openAIRequestWithTools()}
}

func TestExecuteRejectsToolNotInAllowedList(t *testing.T) {
	t.Parallel()

	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		allowedListSettings(),
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("delete_db", `{"id":1}`)},
	)

	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on reject, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusForbidden)
	}
	if pe.Type != typeToolNotInList {
		t.Fatalf("type = %q, want %q", pe.Type, typeToolNotInList)
	}
}

func TestExecuteRejectsSchemaInvalid(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"rules": []any{
			map[string]any{"validator": "json_schema", "behavior": "reject_response"},
		},
	}
	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		settings,
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("send_email", `{"subject":"hi"}`)},
	)

	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on reject, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.Type != typeToolSchemaInvalid {
		t.Fatalf("type = %q, want %q", pe.Type, typeToolSchemaInvalid)
	}
}

func TestExecutePassesAllowedToolCall(t *testing.T) {
	t.Parallel()

	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		allowedListSettings(),
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("send_email", `{"to":"a@b.com"}`)},
	)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through, got %+v", res)
	}
}

func TestExecuteObserveModeDoesNotReject(t *testing.T) {
	t.Parallel()

	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		allowedListSettings(),
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("delete_db", `{"id":1}`)},
	)
	in.Mode = policy.ModeObserve

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("observe mode must not error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through in observe mode, got %+v", res)
	}
}

func TestExecuteFailOpenEnvelope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		req  *infracontext.RequestContext
		resp *infracontext.ResponseContext
	}{
		{
			name: "nil request",
			req:  nil,
			resp: &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("delete_db", `{}`)},
		},
		{
			name: "empty response body",
			req:  openAIRequest(),
			resp: &infracontext.ResponseContext{StatusCode: 200, Body: nil},
		},
		{
			name: "streaming response",
			req:  openAIRequest(),
			resp: &infracontext.ResponseContext{StatusCode: 200, Streaming: true, Body: openAIResponseWithToolCall("delete_db", `{}`)},
		},
		{
			name: "no tool calls",
			req:  openAIRequest(),
			resp: &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseNoToolCalls()},
		},
		{
			name: "undecodable response body",
			req:  openAIRequest(),
			resp: &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{not valid json`)},
		},
		{
			name: "empty provider",
			req:  &infracontext.RequestContext{Body: openAIRequestWithTools()},
			resp: &infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("delete_db", `{}`)},
		},
	}

	p := New(adapter.NewRegistry(), nil, nil)
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			res, err := p.Execute(context.Background(), newExecInput(allowedListSettings(), c.req, c.resp))
			if err != nil {
				t.Fatalf("expected fail-open pass, got error %v", err)
			}
			if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
				t.Fatalf("expected pass-through, got %+v", res)
			}
		})
	}
}
