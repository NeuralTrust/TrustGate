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
	"sort"
	"strings"
)

type mcpToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mcpToolResult struct {
	Content           []mcpContentBlock `json:"content"`
	StructuredContent json.RawMessage   `json:"structuredContent"`
	IsError           bool              `json:"isError"`
}

type mcpContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// mcpInputText returns the tool name plus every string value flattened from the
// arguments tree, newline-joined. It falls back to the raw arguments string when
// the arguments are not decodable, and returns "" when nothing is inspectable.
func mcpInputText(body []byte) string {
	var call mcpToolCall
	if err := json.Unmarshal(body, &call); err != nil {
		return ""
	}
	parts := make([]string, 0, 4)
	if name := strings.TrimSpace(call.Name); name != "" {
		parts = append(parts, name)
	}
	parts = append(parts, flattenArgumentStrings(call.Arguments)...)
	return strings.Join(parts, "\n")
}

// mcpOutputText concatenates the inspectable text of a CallToolResult: the text
// of every text content block (ignoring image/audio/resource blocks) followed by
// every string leaf of structuredContent, in the order rewriteMCPResponse writes
// them back. The isError flag does not change extraction. It returns "" when
// there is nothing to inspect.
//
// structuredContent is included because a tool may return its payload there
// instead of, or in addition to, text blocks — it reaches the agent all the
// same. This value gates whether the guard is called at all, so leaving
// structuredContent out let a result whose PII lived only in structuredContent
// skip inspection entirely and reach the caller unmasked.
func mcpOutputText(body []byte) string {
	var result mcpToolResult
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	parts := make([]string, 0, len(result.Content))
	for _, block := range result.Content {
		if !blockIsText(block) || strings.TrimSpace(block.Text) == "" {
			continue
		}
		parts = append(parts, block.Text)
	}
	parts = append(parts, flattenArgumentStrings(result.StructuredContent)...)
	return strings.Join(parts, "\n")
}

// mcpOutputInspectable reports whether an MCP result body has text worth sending
// to TrustGuard: CallToolResult text blocks or tools/list tool metadata.
func mcpOutputInspectable(body []byte) bool {
	if strings.TrimSpace(mcpOutputText(body)) != "" {
		return true
	}
	var listed struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		return false
	}
	return len(listed.Tools) > 0
}

// flattenArgumentStrings walks the decoded arguments value and collects string
// leaves (recursing maps and arrays); numbers, bools and nulls are skipped. Map
// keys are visited in sorted order for deterministic output. When arguments are
// not valid JSON it returns the raw trimmed arguments so free-form input stays
// inspectable.
func flattenArgumentStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		if trimmed := strings.TrimSpace(string(raw)); trimmed != "" {
			return []string{trimmed}
		}
		return nil
	}
	return collectStrings(decoded, nil)
}

func collectStrings(value any, acc []string) []string {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			acc = append(acc, v)
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			acc = collectStrings(v[k], acc)
		}
	case []any:
		for _, item := range v {
			acc = collectStrings(item, acc)
		}
	}
	return acc
}

func blockIsText(block mcpContentBlock) bool {
	if block.Type == "" {
		return block.Text != ""
	}
	return block.Type == "text"
}

// mcpToolsCallPayload wraps Gate's {name,arguments} tools/call params in the
// JSON-RPC envelope TrustGuard expects for protocol=mcp.
func mcpToolsCallPayload(body []byte) (json.RawMessage, error) {
	var call mcpToolCall
	if err := json.Unmarshal(body, &call); err != nil {
		return nil, err
	}
	params := map[string]any{"name": call.Name}
	if len(call.Arguments) > 0 {
		var args any
		if err := json.Unmarshal(call.Arguments, &args); err != nil {
			params["arguments"] = string(call.Arguments)
		} else {
			params["arguments"] = args
		}
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  params,
	})
}

// mcpToolsResultPayload wraps a CallToolResult body as a JSON-RPC result
// envelope for protocol=mcp output evaluation.
func mcpToolsResultPayload(body []byte) (json.RawMessage, error) {
	var result any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  result,
	})
}

func llmPayload(input string) (json.RawMessage, error) {
	return json.Marshal(GuardPayload{Input: input})
}
