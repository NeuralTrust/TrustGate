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

package promptcompression

import (
	"bytes"
	"encoding/json"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The canonical decode/encode round-trip this plugin rides on is lossy for
// request shapes the canonical model does not represent: multimodal content
// parts (image_url, input_audio, documents) are flattened to text, per-part
// annotations such as Anthropic cache_control are dropped, and top-level
// fields the adapter does not model (seed, n, penalties) disappear on encode.
// A compression plugin must never trade tokens for silent data loss, so the
// guards in this file detect those shapes up front and make Execute pass the
// request through untouched instead.

// supportedFormat restricts the plugin to wire formats whose request shape the
// structural scanner below understands and whose round-trip has verified
// coverage: OpenAI-compatible Chat Completions (openai, azure, groq, deepseek,
// xai, openrouter) and Anthropic Messages.
func supportedFormat(f adapter.Format) bool {
	return adapter.IsSameWireFormat(f, adapter.FormatOpenAI) || f == adapter.FormatAnthropic
}

// allowed key sets for the message shapes the canonical model round-trips
// faithfully. Anything outside these sets is assumed to be dropped by the
// decode/encode cycle and vetoes compression for the whole request.
// Anthropic tool_result parts are deliberately absent: the adapter cannot
// round-trip their array-form content, is_error flag, or adjacency to text
// parts, so any request carrying them is left untouched.
var (
	allowedMessageKeys = keySet("role", "content", "tool_calls", "tool_call_id")
	allowedPartKeys    = map[string]map[string]struct{}{
		"text":     keySet("type", "text"),
		"tool_use": keySet("type", "id", "name", "input"),
	}
	allowedToolCallKeys = keySet("id", "type", "function", "index")
	allowedFunctionKeys = keySet("name", "arguments")

	// tool definitions: OpenAI {type, function{...}} and Anthropic
	// {name, description, input_schema}. Extra keys such as an Anthropic
	// cache_control breakpoint or OpenAI function.strict are not modeled by
	// the canonical form and veto compression.
	allowedOpenAIToolKeys    = keySet("type", "function")
	allowedToolFunctionKeys  = keySet("name", "description", "parameters")
	allowedAnthropicToolKeys = keySet("name", "description", "input_schema")

	// tool_choice objects: OpenAI {type, function{name}} and Anthropic
	// {type, name}. Fields like disable_parallel_tool_use veto compression.
	allowedToolChoiceKeys   = keySet("type", "name", "function")
	allowedToolChoiceFnKeys = keySet("name")
)

func keySet(keys ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		s[k] = struct{}{}
	}
	return s
}

// roundTripSafe reports whether every message, tool definition, and
// tool_choice in the raw request body uses only shapes the canonical model
// represents without loss. It is conservative: any parse surprise or unknown
// key vetoes compression.
func roundTripSafe(body []byte) bool {
	var probe struct {
		Messages   []json.RawMessage `json:"messages"`
		Tools      []json.RawMessage `json:"tools"`
		ToolChoice json.RawMessage   `json:"tool_choice"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	systemSeen := false
	for i, raw := range probe.Messages {
		role, ok := messageRoundTripSafe(raw)
		if !ok {
			return false
		}
		// The canonical form hoists system content into a single field, so a
		// system message anywhere but the head — or more than one — would be
		// merged and reordered on re-encode.
		if role == "system" {
			if i != 0 || systemSeen {
				return false
			}
			systemSeen = true
		}
	}
	for _, raw := range probe.Tools {
		if !toolRoundTripSafe(raw) {
			return false
		}
	}
	return toolChoiceRoundTripSafe(probe.ToolChoice)
}

func messageRoundTripSafe(raw json.RawMessage) (role string, safe bool) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return "", false
	}
	for key := range msg {
		if _, ok := allowedMessageKeys[key]; !ok {
			return "", false
		}
	}
	if rawRole, ok := msg["role"]; ok {
		if err := json.Unmarshal(rawRole, &role); err != nil {
			return "", false
		}
	}
	if content, ok := msg["content"]; ok && !contentRoundTripSafe(content) {
		return "", false
	}
	if calls, ok := msg["tool_calls"]; ok && !toolCallsRoundTripSafe(calls) {
		return "", false
	}
	return role, true
}

// contentRoundTripSafe accepts plain string (or null) content, and content
// arrays whose every part is a known text-bearing shape with no extra
// annotations (an Anthropic cache_control marker, for example, must survive
// byte-for-byte or not be touched at all).
func contentRoundTripSafe(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	if trimmed[0] == '"' {
		return json.Valid(trimmed)
	}
	if trimmed[0] != '[' {
		return false
	}
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &parts); err != nil {
		return false
	}
	for _, part := range parts {
		var partType string
		if err := json.Unmarshal(part["type"], &partType); err != nil {
			return false
		}
		allowed, ok := allowedPartKeys[partType]
		if !ok {
			return false
		}
		for key := range part {
			if _, ok := allowed[key]; !ok {
				return false
			}
		}
	}
	return true
}

func toolCallsRoundTripSafe(raw json.RawMessage) bool {
	var calls []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &calls); err != nil {
		return false
	}
	for _, call := range calls {
		for key := range call {
			if _, ok := allowedToolCallKeys[key]; !ok {
				return false
			}
		}
		if fn, ok := call["function"]; ok {
			var function map[string]json.RawMessage
			if err := json.Unmarshal(fn, &function); err != nil {
				return false
			}
			for key := range function {
				if _, ok := allowedFunctionKeys[key]; !ok {
					return false
				}
			}
		}
	}
	return true
}

// toolRoundTripSafe accepts the two tool-definition shapes the canonical
// model represents: OpenAI {type, function{name, description, parameters}}
// and Anthropic {name, description, input_schema}. The shape is picked by the
// presence of "function" so a hybrid object cannot borrow keys from both sets.
func toolRoundTripSafe(raw json.RawMessage) bool {
	var tool map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tool); err != nil {
		return false
	}
	if fn, ok := tool["function"]; ok {
		for key := range tool {
			if _, ok := allowedOpenAIToolKeys[key]; !ok {
				return false
			}
		}
		var function map[string]json.RawMessage
		if err := json.Unmarshal(fn, &function); err != nil {
			return false
		}
		for key := range function {
			if _, ok := allowedToolFunctionKeys[key]; !ok {
				return false
			}
		}
		return true
	}
	for key := range tool {
		if _, ok := allowedAnthropicToolKeys[key]; !ok {
			return false
		}
	}
	return true
}

// toolChoiceRoundTripSafe accepts an absent tool_choice, the OpenAI string
// form ("auto", "none", "required"), and the object forms the canonical model
// carries: OpenAI {type, function{name}} and Anthropic {type, name}.
func toolChoiceRoundTripSafe(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	if trimmed[0] == '"' {
		return json.Valid(trimmed)
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &choice); err != nil {
		return false
	}
	for key := range choice {
		if _, ok := allowedToolChoiceKeys[key]; !ok {
			return false
		}
	}
	if fn, ok := choice["function"]; ok {
		var function map[string]json.RawMessage
		if err := json.Unmarshal(fn, &function); err != nil {
			return false
		}
		for key := range function {
			if _, ok := allowedToolChoiceFnKeys[key]; !ok {
				return false
			}
		}
	}
	return true
}

// keepsTopLevelFields reports whether every non-null top-level field of the
// original request survived into the re-encoded body. The transforms only
// rewrite string values inside messages, so a top-level key missing from the
// output means the adapter's canonical model dropped it (seed, n, penalties,
// a max_completion_tokens rename) — in that case the original request is
// forwarded instead.
func keepsTopLevelFields(original, encoded []byte) bool {
	var in, out map[string]json.RawMessage
	if err := json.Unmarshal(original, &in); err != nil {
		return false
	}
	if err := json.Unmarshal(encoded, &out); err != nil {
		return false
	}
	for key, value := range in {
		trimmed := bytes.TrimSpace(value)
		if bytes.Equal(trimmed, []byte("null")) {
			continue
		}
		// An explicit "stream": false is the provider default; the adapter
		// omitting it on encode is faithful, not lossy.
		if key == "stream" && bytes.Equal(trimmed, []byte("false")) {
			continue
		}
		if _, ok := out[key]; !ok {
			return false
		}
	}
	return true
}
