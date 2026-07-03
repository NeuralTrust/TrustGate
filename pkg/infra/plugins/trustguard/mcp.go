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
	Content []mcpContentBlock `json:"content"`
	IsError bool              `json:"isError"`
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

// mcpOutputText concatenates the text of every text content block in a
// CallToolResult, ignoring non-text blocks (image/audio/resource). The isError
// flag does not change extraction. It returns "" when there is no text.
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
	return strings.Join(parts, "\n")
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
