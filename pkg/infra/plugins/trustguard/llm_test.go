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
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestLLMRequestPayloadPreservesToolRoles(t *testing.T) {
	t.Parallel()

	creq := &adapter.CanonicalRequest{
		System: "be safe",
		Messages: []adapter.CanonicalMessage{
			{Role: "user", Content: "get weather"},
			{
				Role:    "assistant",
				Content: "",
				ToolCalls: []adapter.CanonicalToolCall{{
					ID:        "call_1",
					Name:      "get_weather",
					Arguments: `{"city":"Paris"}`,
				}},
			},
			{Role: "tool", Content: `{"temp":18}`, ToolCallID: "call_1"},
		},
	}

	raw, err := llmRequestPayload(creq)
	if err != nil {
		t.Fatalf("llmRequestPayload: %v", err)
	}
	var payload struct {
		Messages []map[string]any `json:"messages"`
		Input    string           `json:"input"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Input != "" {
		t.Fatalf("input = %q, want empty (roles must not be flattened)", payload.Input)
	}
	if len(payload.Messages) != 4 {
		t.Fatalf("messages len = %d, want 4", len(payload.Messages))
	}
	if payload.Messages[0]["role"] != "system" || payload.Messages[0]["content"] != "be safe" {
		t.Fatalf("system message = %#v", payload.Messages[0])
	}
	if payload.Messages[1]["role"] != "user" {
		t.Fatalf("user role = %#v", payload.Messages[1]["role"])
	}
	if payload.Messages[2]["role"] != "assistant" {
		t.Fatalf("assistant role = %#v", payload.Messages[2]["role"])
	}
	if payload.Messages[2]["content"] != nil {
		t.Fatalf("assistant content = %#v, want null", payload.Messages[2]["content"])
	}
	calls, ok := payload.Messages[2]["tool_calls"].([]any)
	if !ok || len(calls) != 1 {
		t.Fatalf("tool_calls = %#v", payload.Messages[2]["tool_calls"])
	}
	if payload.Messages[3]["role"] != "tool" {
		t.Fatalf("tool role = %#v", payload.Messages[3]["role"])
	}
	if payload.Messages[3]["content"] != `{"temp":18}` {
		t.Fatalf("tool content = %#v", payload.Messages[3]["content"])
	}
	if payload.Messages[3]["tool_call_id"] != "call_1" {
		t.Fatalf("tool_call_id = %#v", payload.Messages[3]["tool_call_id"])
	}
}

func TestJoinedTransformedMessages(t *testing.T) {
	t.Parallel()

	got, ok := joinedTransformedMessages(map[string]any{
		"messages": []any{
			map[string]any{"role": "system", "content": "be safe"},
			map[string]any{"role": "user", "content": "hello"},
			map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{}},
			map[string]any{"role": "tool", "content": "weather ok"},
		},
	})
	if !ok {
		t.Fatal("expected joined text")
	}
	if got != "be safe\nhello\nweather ok" {
		t.Fatalf("joined = %q, want system/user/tool contents", got)
	}
}

func TestTransformedInputPrefersInputThenMessages(t *testing.T) {
	t.Parallel()

	if got, ok := transformedInput(map[string]any{"input": "flat"}); !ok || got != "flat" {
		t.Fatalf("input key: got %q ok=%v", got, ok)
	}
	got, ok := transformedInput(map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "a"},
			map[string]any{"role": "tool", "content": "b"},
		},
	})
	if !ok || got != "a\nb" {
		t.Fatalf("messages fallback: got %q ok=%v", got, ok)
	}
}
