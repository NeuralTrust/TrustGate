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
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// streamAssistantText reassembles assistant text from a buffered SSE body.
// Prefer streamCanonicalResponse when tool_calls or reasoning must be preserved.
func streamAssistantText(reg *adapter.Registry, body []byte, format adapter.Format) string {
	cresp := streamCanonicalResponse(reg, body, format)
	if cresp == nil {
		return ""
	}
	return cresp.Content
}

// streamCanonicalResponse reassembles a CanonicalResponse from a buffered SSE
// body using per-chunk DecodeStreamChunk. Captures content deltas, reasoning
// deltas, and tool_call deltas (merged by index). Returns nil when the body
// yields nothing inspectable.
func streamCanonicalResponse(reg *adapter.Registry, body []byte, format adapter.Format) *adapter.CanonicalResponse {
	if reg == nil || len(body) == 0 {
		return nil
	}
	var content strings.Builder
	var reasoning strings.Builder
	toolCalls := map[int]*adapter.CanonicalToolCall{}
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		chunk, err := reg.DecodeStreamChunkFor([]byte(payload), format)
		if err != nil || chunk == nil {
			continue
		}
		if chunk.Delta != "" {
			content.WriteString(chunk.Delta)
		}
		if chunk.ReasoningDelta != "" {
			reasoning.WriteString(chunk.ReasoningDelta)
		}
		for _, tc := range chunk.ToolCallDeltas {
			mergeStreamToolCall(toolCalls, tc)
		}
	}
	cresp := &adapter.CanonicalResponse{
		Content:   content.String(),
		ToolCalls: toolCallsByIndex(toolCalls),
	}
	if r := reasoning.String(); r != "" {
		cresp.Reasoning = &adapter.CanonicalReasoning{ThinkingText: r}
	}
	if cresp.Content == "" && cresp.Reasoning == nil && len(cresp.ToolCalls) == 0 {
		return nil
	}
	return cresp
}

func mergeStreamToolCall(dst map[int]*adapter.CanonicalToolCall, delta adapter.StreamToolCallDelta) {
	tc, ok := dst[delta.Index]
	if !ok {
		tc = &adapter.CanonicalToolCall{}
		dst[delta.Index] = tc
	}
	if delta.ID != "" {
		tc.ID = delta.ID
	}
	if delta.Name != "" {
		tc.Name = delta.Name
	}
	if delta.ArgumentsDelta != "" {
		tc.Arguments += delta.ArgumentsDelta
	}
}

func toolCallsByIndex(src map[int]*adapter.CanonicalToolCall) []adapter.CanonicalToolCall {
	if len(src) == 0 {
		return nil
	}
	indexes := make([]int, 0, len(src))
	for idx := range src {
		indexes = append(indexes, idx)
	}
	sort.Ints(indexes)
	out := make([]adapter.CanonicalToolCall, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, *src[idx])
	}
	return out
}
