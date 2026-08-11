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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestStreamAssistantTextOpenAICompletions(t *testing.T) {
	t.Parallel()

	reg := adapter.NewRegistry()
	sse := "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n" +
		"data: [DONE]\n"
	got := streamAssistantText(reg, []byte(sse), adapter.FormatOpenAI)
	if got != "hello" {
		t.Fatalf("streamAssistantText = %q, want %q", got, "hello")
	}
}

func TestStreamAssistantTextEmpty(t *testing.T) {
	t.Parallel()

	reg := adapter.NewRegistry()
	if got := streamAssistantText(reg, nil, adapter.FormatOpenAI); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := streamAssistantText(nil, []byte("data: {}\n"), adapter.FormatOpenAI); got != "" {
		t.Fatalf("nil registry got %q, want empty", got)
	}
}

func TestStreamCanonicalResponseContentReasoningToolCalls(t *testing.T) {
	t.Parallel()

	reg := adapter.NewRegistry()
	sse := "" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"think \"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"hard\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi \"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"there\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"search\",\"arguments\":\"{\\\"q\\\"\"}}]}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"x\\\"}\"}}]}}]}\n" +
		"data: [DONE]\n"

	got := streamCanonicalResponse(reg, []byte(sse), adapter.FormatOpenAI)
	if got == nil {
		t.Fatal("expected canonical response")
	}
	if got.Content != "hi there" {
		t.Fatalf("content = %q, want %q", got.Content, "hi there")
	}
	if got.Reasoning == nil || got.Reasoning.ThinkingText != "think hard" {
		t.Fatalf("reasoning = %#v, want ThinkingText=%q", got.Reasoning, "think hard")
	}
	if len(got.ToolCalls) != 1 {
		t.Fatalf("tool_calls len = %d, want 1", len(got.ToolCalls))
	}
	tc := got.ToolCalls[0]
	if tc.ID != "call_1" || tc.Name != "search" || tc.Arguments != `{"q":"x"}` {
		t.Fatalf("tool_call = %#v", tc)
	}
}

func TestStreamCanonicalResponseKeepaliveAndEmpty(t *testing.T) {
	t.Parallel()

	reg := adapter.NewRegistry()
	sse := ": keepalive\n\ndata: [DONE]\n"
	if got := streamCanonicalResponse(reg, []byte(sse), adapter.FormatOpenAI); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
}
