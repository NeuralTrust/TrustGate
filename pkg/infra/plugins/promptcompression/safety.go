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
var (
	allowedMessageKeys = keySet("role", "content", "tool_calls", "tool_call_id")
	allowedPartKeys    = map[string]map[string]struct{}{
		"text":        keySet("type", "text"),
		"tool_use":    keySet("type", "id", "name", "input"),
		"tool_result": keySet("type", "tool_use_id", "content", "is_error"),
	}
	allowedToolCallKeys = keySet("id", "type", "function", "index")
	allowedFunctionKeys = keySet("name", "arguments")
)

func keySet(keys ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		s[k] = struct{}{}
	}
	return s
}

// roundTripSafe reports whether every message in the raw request body uses
// only shapes the canonical model represents without loss. It is conservative:
// any parse surprise or unknown key vetoes compression.
func roundTripSafe(body []byte) bool {
	var probe struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	for _, raw := range probe.Messages {
		if !messageRoundTripSafe(raw) {
			return false
		}
	}
	return true
}

func messageRoundTripSafe(raw json.RawMessage) bool {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	for key := range msg {
		if _, ok := allowedMessageKeys[key]; !ok {
			return false
		}
	}
	if content, ok := msg["content"]; ok && !contentRoundTripSafe(content) {
		return false
	}
	if calls, ok := msg["tool_calls"]; ok && !toolCallsRoundTripSafe(calls) {
		return false
	}
	return true
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
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			continue
		}
		if _, ok := out[key]; !ok {
			return false
		}
	}
	return true
}
