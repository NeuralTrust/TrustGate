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
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// echoTransform answers the way TrustGuard's DLP does on a protocol=llm
// transform: it echoes the messages[] it was sent, with every string content
// passed through mask, under transformed_payload.
func echoTransform(raw json.RawMessage, mask func(string) string) GuardResponse {
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	msgs, _ := payload["messages"].([]any)
	for _, m := range msgs {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := mm["content"].(string); ok {
			mm["content"] = mask(c)
		}
		calls, _ := mm["tool_calls"].([]any)
		for _, c := range calls {
			fn, _ := c.(map[string]any)["function"].(map[string]any)
			if args, ok := fn["arguments"].(string); ok {
				// TrustGuard parses JSON arguments and re-marshals them, which
				// sorts the keys even when nothing was masked.
				var v any
				if json.Unmarshal([]byte(args), &v) == nil {
					b, _ := json.Marshal(v)
					args = string(b)
				}
				fn["arguments"] = mask(args)
			}
		}
	}
	return GuardResponse{
		Status:             statusTransform,
		TransformedPayload: map[string]any{"messages": msgs},
		Findings: []GuardFinding{{
			Source:  &GuardFindingSource{Kind: "detector", Plugin: "data_loss_prevention"},
			Signal:  &GuardFindingSignal{Type: "secret"},
			Outcome: &GuardFindingOutcome{Action: "transform"},
		}},
	}
}

// Built at run time so the secret scanner does not flag a fixture as a leak.
var testOpenAIKey = "sk-" + "proj-" + strings.Repeat("aB3dE5fG7h", 5)

const testPEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabc\ndef123\n-----END RSA PRIVATE KEY-----"

// A DLP transform must rewrite the request, never degrade into a 403. Both
// failing shapes used to: a system prompt with surrounding whitespace (sent
// trimmed, counted untrimmed) and a multi-line secret whose mask is one line.
func TestExecutePreRequestTransformMessagesRewritesBody(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		secret string
		mask   string
	}{
		{
			name:   "single-line secret",
			body:   chatBody(t, "be safe", "key "+testOpenAIKey),
			secret: testOpenAIKey, mask: "[MASKED_OPENAI_KEY]",
		},
		{
			name:   "system prompt ends in newline",
			body:   chatBody(t, "be safe\n", "key "+testOpenAIKey),
			secret: testOpenAIKey, mask: "[MASKED_OPENAI_KEY]",
		},
		{
			name:   "system prompt starts with newline",
			body:   chatBody(t, "\nbe safe", "key "+testOpenAIKey),
			secret: testOpenAIKey, mask: "[MASKED_OPENAI_KEY]",
		},
		{
			name:   "multi-line private key collapses to one token",
			body:   chatBody(t, "be safe", "key:\n"+testPEM+"\nthanks"),
			secret: testPEM, mask: "[MASKED_PRIVATE_KEY]",
		},
		{
			name: "editor client: array content, history, trailing newline",
			body: `{"model":"gpt-4o","stream":true,"messages":[
				{"role":"system","content":"You are a coding assistant.\n\n## Rules\n- be brief\n"},
				{"role":"user","content":[{"type":"text","text":"what does this do?"}]},
				{"role":"assistant","content":"It prints a value.\n"},
				{"role":"user","content":[{"type":"text","text":"my key is ` + testOpenAIKey + `"}]}]}`,
			secret: testOpenAIKey, mask: "[MASKED_OPENAI_KEY]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{echoMask: func(s string) string { return strings.ReplaceAll(s, tc.secret, tc.mask) }}
			res, extras, err := runTransform(t, f, tc.body)
			if err != nil || res == nil || res.StatusCode != http.StatusOK {
				t.Fatalf("transform degraded to block: err=%v degraded_reason=%q", err, extras.DegradedReason)
			}
			if extras.Decision != decisionTransformed {
				t.Fatalf("decision = %q, want %q", extras.Decision, decisionTransformed)
			}
			got := decodeOpenAIRequest(t, res.RequestBody)
			joined := strings.Join(got, "\x00")
			if strings.Contains(joined, tc.secret) || !strings.Contains(joined, tc.mask) {
				t.Fatalf("body not masked: %q", got)
			}
		})
	}
}

// The system prompt is sent trimmed; writing it back must restore the
// whitespace so only the masked span changes.
func TestExecutePreRequestTransformMessagesKeepsSystemWhitespace(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{echoMask: func(s string) string { return strings.ReplaceAll(s, testOpenAIKey, "[MASKED_OPENAI_KEY]") }}
	res, extras, err := runTransform(t, f, chatBody(t, "\n  be safe\n\n", "key "+testOpenAIKey))
	if err != nil || res == nil {
		t.Fatalf("unexpected block: err=%v degraded_reason=%q", err, extras.DegradedReason)
	}
	got := decodeOpenAIRequest(t, res.RequestBody)
	if got[0] != "\n  be safe\n\n" {
		t.Fatalf("system = %q, want original whitespace kept", got[0])
	}
	if got[1] != "key [MASKED_OPENAI_KEY]" {
		t.Fatalf("user = %q", got[1])
	}
}

// A messages[] echo that does not line up with what was sent is ambiguous, so
// the mask cannot be applied. That is a failure on our side and follows
// on_error: by default the request goes on unmasked and the span says why.
func TestExecutePreRequestTransformMessagesMismatchFailsOpen(t *testing.T) {
	t.Parallel()
	cases := map[string][]any{
		"missing message": {
			map[string]any{"role": "system", "content": "be safe"},
		},
		"role out of order": {
			map[string]any{"role": "user", "content": "be safe"},
			map[string]any{"role": "system", "content": "key [MASKED_OPENAI_KEY]"},
		},
		"non-string content": {
			map[string]any{"role": "system", "content": "be safe"},
			map[string]any{"role": "user", "content": []any{"key"}},
		},
	}
	for name, msgs := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resp := echoTransform(nil, nil)
			resp.TransformedPayload = map[string]any{"messages": msgs}
			f := &fakeGuard{response: resp}
			res, extras, err := runTransform(t, f, chatBody(t, "be safe", "key "+testOpenAIKey))
			if err != nil || res == nil || res.StopUpstream || res.RequestBody != nil {
				t.Fatalf("expected an untouched pass-through, got res=%+v err=%v", res, err)
			}
			if !extras.FailedOpen || extras.FailureReason != failureReasonTransformFailed {
				t.Fatalf("extras = %+v, want failed_open %q", extras, failureReasonTransformFailed)
			}
			if extras.DegradedReason != reasonTransformEncodeFailed {
				t.Fatalf("degraded_reason = %q, want %q", extras.DegradedReason, reasonTransformEncodeFailed)
			}
		})
	}
}

func runTransform(t *testing.T, f *fakeGuard, body string) (*appplugins.Result, guardData, error) {
	t.Helper()
	srv := newServer(t, f)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	req := requestContext()
	req.Body = []byte(body)
	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))
	extras, _ := span.PluginAttrsCopy().Extras.(guardData)
	return res, extras, err
}

func chatBody(t *testing.T, system, user string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// decodeOpenAIRequest returns every message content of an OpenAI chat body,
// flattening array parts, in order.
func decodeOpenAIRequest(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode rewritten body: %v", err)
	}
	out := make([]string, 0, len(req.Messages))
	for _, m := range req.Messages {
		var s string
		if json.Unmarshal(m.Content, &s) == nil {
			out = append(out, s)
			continue
		}
		var parts []struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(m.Content, &parts)
		texts := make([]string, 0, len(parts))
		for _, p := range parts {
			texts = append(texts, p.Text)
		}
		out = append(out, strings.Join(texts, "\n"))
	}
	return out
}

// TrustGuard masks secrets inside tool_calls arguments as well. The masked
// arguments must reach the provider: before, only content was written back and
// the unchanged-body shortcut forwarded the original bytes, secret included.
func TestExecutePreRequestTransformMessagesMasksToolArguments(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-4o","messages":[
		{"role":"user","content":"deploy it"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"deploy","arguments":"{\"token\":\"` + testOpenAIKey + `\",\"env\":\"dev\"}"}}]},
		{"role":"tool","tool_call_id":"c1","content":"ok"}]}`
	f := &fakeGuard{echoMask: func(s string) string { return strings.ReplaceAll(s, testOpenAIKey, "[MASKED_OPENAI_KEY]") }}
	res, extras, err := runTransform(t, f, body)
	if err != nil || res == nil {
		t.Fatalf("unexpected block: err=%v degraded_reason=%q", err, extras.DegradedReason)
	}
	got := string(res.RequestBody)
	if strings.Contains(got, testOpenAIKey) {
		t.Fatalf("secret in tool arguments forwarded unmasked: %s", got)
	}
	if !strings.Contains(got, "[MASKED_OPENAI_KEY]") {
		t.Fatalf("masked argument missing: %s", got)
	}
}

// Arguments TrustGuard re-marshals without masking anything (key order
// changes) are not a change: the original body is forwarded byte for byte.
func TestExecutePreRequestTransformMessagesKeepsReorderedArguments(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"key ` + testOpenAIKey + `"},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"b\":1,\"a\":2}"}}]},{"role":"tool","tool_call_id":"c1","content":"ok"}]}`
	f := &fakeGuard{echoMask: func(s string) string { return s }}
	res, extras, err := runTransform(t, f, body)
	if err != nil || res == nil {
		t.Fatalf("unexpected block: err=%v degraded_reason=%q", err, extras.DegradedReason)
	}
	if string(res.RequestBody) != body {
		t.Fatalf("unchanged request was re-encoded:\n got %s\nwant %s", res.RequestBody, body)
	}
}
