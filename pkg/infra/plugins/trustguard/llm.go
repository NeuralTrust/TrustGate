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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// llmRequestPayload builds a protocol=llm evaluate payload that preserves chat
// roles (including role=tool responses and assistant tool_calls). Flattening to
// {input} loses roles, so detectors that only inspect tool content cannot run.
func llmRequestPayload(creq *adapter.CanonicalRequest) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"messages": guardChatMessages(creq),
	})
}

func guardChatMessages(creq *adapter.CanonicalRequest) []map[string]any {
	if creq == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(creq.Messages)+1)
	if s := strings.TrimSpace(creq.System); s != "" {
		out = append(out, map[string]any{
			"role":    "system",
			"content": s,
		})
	}
	for _, msg := range creq.Messages {
		out = append(out, guardChatMessage(msg))
	}
	return out
}

func guardChatMessage(msg adapter.CanonicalMessage) map[string]any {
	m := map[string]any{
		"role": msg.Role,
	}
	if len(msg.ToolCalls) > 0 {
		calls := make([]map[string]any, 0, len(msg.ToolCalls))
		for _, tc := range msg.ToolCalls {
			calls = append(calls, map[string]any{
				"id":   tc.ID,
				"type": "function",
				"function": map[string]any{
					"name":      tc.Name,
					"arguments": tc.Arguments,
				},
			})
		}
		m["tool_calls"] = calls
		if strings.TrimSpace(msg.Content) == "" {
			m["content"] = nil
		} else {
			m["content"] = msg.Content
		}
	} else {
		m["content"] = msg.Content
	}
	if msg.ToolCallID != "" {
		m["tool_call_id"] = msg.ToolCallID
	}
	return m
}

// joinedTransformedMessages rebuilds the newline-joined text TrustGate uses for
// request rewrite from a Guard transformed_payload that carries messages[].
// Order matches requestParts: system (as role=system) then each non-empty content.
func joinedTransformedMessages(payload map[string]any) (string, bool) {
	raw, ok := payload["messages"]
	if !ok || raw == nil {
		return "", false
	}
	arr, ok := raw.([]any)
	if !ok || len(arr) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, ok := m["content"].(string)
		if !ok || strings.TrimSpace(content) == "" {
			continue
		}
		parts = append(parts, content)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "\n"), true
}
