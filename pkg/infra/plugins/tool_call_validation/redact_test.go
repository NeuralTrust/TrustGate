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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func completionsBodyTwoCalls(args0, args1 string) []byte {
	tc0 := `{"id":"call_0","type":"function","function":{"name":"run_shell","arguments":` + quote(args0) + `}}`
	tc1 := `{"id":"call_1","type":"function","function":{"name":"run_shell","arguments":` + quote(args1) + `}}`
	return []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[` + tc0 + `,` + tc1 + `]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
}

func responsesBody(args string) []byte {
	item := `{"type":"function_call","call_id":"call_0","name":"run_shell","arguments":` + quote(args) + `}`
	reasoning := `{"type":"reasoning","id":"rs_1"}`
	return []byte(`{"id":"resp_1","object":"response","model":"gpt-4o","output":[` + reasoning + `,` + item + `],"status":"completed"}`)
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func decodeToolCalls(t *testing.T, body []byte, format adapter.Format) []adapter.CanonicalToolCall {
	t.Helper()
	cresp, err := adapter.NewRegistry().DecodeResponseFor(body, format)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	return cresp.ToolCalls
}

func TestApplyRedactionsCompletionsSubstring(t *testing.T) {
	t.Parallel()

	body := completionsBodyTwoCalls(`{"code":"sudo rm -rf /"}`, `{"code":"echo hi"}`)
	reds := []redaction{{callIndex: 0, path: "$.code", terms: []string{"rm -rf"}, replaceWith: "[REDACTED]"}}

	patched, changed := applyRedactions(body, adapter.FormatOpenAI, reds)
	if !changed {
		t.Fatalf("expected change")
	}
	if !json.Valid(patched) {
		t.Fatalf("patched body is not valid JSON")
	}

	calls := decodeToolCalls(t, patched, adapter.FormatOpenAI)
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(calls))
	}
	if strings.Contains(calls[0].Arguments, "rm -rf") {
		t.Fatalf("denied substring not redacted: %s", calls[0].Arguments)
	}
	if !strings.Contains(calls[0].Arguments, "[REDACTED]") {
		t.Fatalf("replacement missing: %s", calls[0].Arguments)
	}
	if calls[1].Arguments != `{"code":"echo hi"}` {
		t.Fatalf("sibling tool call changed: %s", calls[1].Arguments)
	}
	if !bytes.Contains(patched, []byte(`"id":"chatcmpl-1"`)) {
		t.Fatalf("envelope id not preserved")
	}
	if !bytes.Contains(patched, []byte(`"total_tokens":3`)) {
		t.Fatalf("usage not preserved")
	}
}

func TestApplyRedactionsCompletionsWholeReplace(t *testing.T) {
	t.Parallel()

	body := completionsBodyTwoCalls(`{"to":"attacker@evil.com"}`, `{"to":"ok@company.com"}`)
	reds := []redaction{{callIndex: 0, path: "$.to", whole: true, replaceWith: "[blocked]"}}

	patched, changed := applyRedactions(body, adapter.FormatOpenAI, reds)
	if !changed {
		t.Fatalf("expected change")
	}
	calls := decodeToolCalls(t, patched, adapter.FormatOpenAI)
	if calls[0].Arguments != `{"to":"[blocked]"}` {
		t.Fatalf("whole-value replacement failed: %s", calls[0].Arguments)
	}
	if calls[1].Arguments != `{"to":"ok@company.com"}` {
		t.Fatalf("sibling tool call changed: %s", calls[1].Arguments)
	}
}

func TestApplyRedactionsDuplicateArgumentsKeyOnIndex(t *testing.T) {
	t.Parallel()

	body := completionsBodyTwoCalls(`{"code":"rm -rf /"}`, `{"code":"rm -rf /"}`)
	reds := []redaction{{callIndex: 1, path: "$.code", terms: []string{"rm -rf"}, replaceWith: "[REDACTED]"}}

	patched, changed := applyRedactions(body, adapter.FormatOpenAI, reds)
	if !changed {
		t.Fatalf("expected change")
	}
	calls := decodeToolCalls(t, patched, adapter.FormatOpenAI)
	if calls[0].Arguments != `{"code":"rm -rf /"}` {
		t.Fatalf("indexed-only redaction mistargeted call 0: %s", calls[0].Arguments)
	}
	if strings.Contains(calls[1].Arguments, "rm -rf") {
		t.Fatalf("call 1 should be redacted: %s", calls[1].Arguments)
	}
}

func TestApplyRedactionsMultiplePathsAccumulate(t *testing.T) {
	t.Parallel()

	body := completionsBodyTwoCalls(`{"code":"rm -rf /","note":"DROP TABLE users"}`, `{"code":"echo hi"}`)
	reds := []redaction{
		{callIndex: 0, path: "$.code", terms: []string{"rm -rf"}, replaceWith: "[REDACTED]"},
		{callIndex: 0, path: "$.note", terms: []string{"DROP TABLE"}, replaceWith: "[REDACTED]"},
	}

	patched, changed := applyRedactions(body, adapter.FormatOpenAI, reds)
	if !changed {
		t.Fatalf("expected change")
	}
	calls := decodeToolCalls(t, patched, adapter.FormatOpenAI)
	if strings.Contains(calls[0].Arguments, "rm -rf") || strings.Contains(calls[0].Arguments, "DROP TABLE") {
		t.Fatalf("accumulated redactions not applied: %s", calls[0].Arguments)
	}
}

func TestApplyRedactionsResponsesFormat(t *testing.T) {
	t.Parallel()

	body := responsesBody(`{"code":"sudo rm -rf /"}`)
	reds := []redaction{{callIndex: 0, path: "$.code", terms: []string{"rm -rf"}, replaceWith: "[REDACTED]"}}

	patched, changed := applyRedactions(body, adapter.FormatOpenAIResponses, reds)
	if !changed {
		t.Fatalf("expected change")
	}
	calls := decodeToolCalls(t, patched, adapter.FormatOpenAIResponses)
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if strings.Contains(calls[0].Arguments, "rm -rf") {
		t.Fatalf("denied substring not redacted: %s", calls[0].Arguments)
	}
	if !bytes.Contains(patched, []byte(`"type":"reasoning"`)) {
		t.Fatalf("unrelated output item not preserved")
	}
}

func TestApplyRedactionsUnsupportedFormatFailsOpen(t *testing.T) {
	t.Parallel()

	body := []byte(`{"content":[{"type":"tool_use","name":"run_shell","input":{"code":"rm -rf /"}}]}`)
	reds := []redaction{{callIndex: 0, path: "$.code", terms: []string{"rm -rf"}, replaceWith: "[REDACTED]"}}

	patched, changed := applyRedactions(body, adapter.FormatAnthropic, reds)
	if changed {
		t.Fatalf("expected fail-open for unsupported format")
	}
	if !bytes.Equal(patched, body) {
		t.Fatalf("body must be unchanged on fail-open")
	}
}
