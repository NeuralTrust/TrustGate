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

package adapter

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

// NormalizeOpenAIRequest performs lightweight, in-place normalization of an
// OpenAI-compatible request body to fix common issues sent by third-party SDKs
// (e.g. Mistral, Cohere) that use the OpenAI wire format but omit fields that
// OpenAI strictly requires.
//
// Current normalizations:
//   - Ensures every tool_call object inside messages has "type": "function".
//     The Mistral SDK omits this field, but OpenAI returns 400 without it.
//   - Ensures every tools[].function.parameters is a non-empty JSON Schema object.
//     Gemini cross-format requests often omit parameters; strict OpenAI-wire
//     upstreams (e.g. Cerebras gpt-oss) reject tools without it.
//   - Ensures every custom tool is nested under "custom" with its grammar under
//     format.grammar. Clients targeting GPT-5 models declare custom tools the
//     Responses way, which chat/completions rejects.
//
// The function is a no-op (returns the original body) when no changes are
// needed, so it is safe to call unconditionally on every OpenAI-bound request.
func NormalizeOpenAIRequest(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}

	changed := false

	if msgsRaw, ok := raw["messages"]; ok {
		var msgs []map[string]json.RawMessage
		if err := json.Unmarshal(msgsRaw, &msgs); err == nil {
			msgsChanged := false
			for i := range msgs {
				tcRaw, hasTCs := msgs[i]["tool_calls"]
				if !hasTCs {
					continue
				}

				var tcs []map[string]json.RawMessage
				if err := json.Unmarshal(tcRaw, &tcs); err != nil {
					continue
				}

				tcChanged := false
				for j := range tcs {
					typeRaw, hasType := tcs[j]["type"]
					if !hasType || isEmptyOrNull(typeRaw) {
						b, _ := json.Marshal("function")
						tcs[j]["type"] = b
						tcChanged = true
					}
				}

				if tcChanged {
					b, err := json.Marshal(tcs)
					if err == nil {
						msgs[i]["tool_calls"] = b
						msgsChanged = true
					}
				}
			}
			if msgsChanged {
				b, err := json.Marshal(msgs)
				if err == nil {
					raw["messages"] = b
					changed = true
				}
			}
		}
	}

	if toolsRaw, ok := raw["tools"]; ok {
		if b, toolsChanged := normalizeToolsFunctionParameters(toolsRaw); toolsChanged {
			toolsRaw = b
			raw["tools"] = b
			changed = true
		}
		if b, toolsChanged := normalizeCustomTools(toolsRaw); toolsChanged {
			raw["tools"] = b
			changed = true
		}
	}

	if !changed {
		return body
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

func normalizeToolsFunctionParameters(toolsRaw json.RawMessage) (json.RawMessage, bool) {
	if len(toolsRaw) == 0 || string(toolsRaw) == "null" {
		return toolsRaw, false
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return toolsRaw, false
	}
	defaultParams, _ := json.Marshal(map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	})
	changed := false
	for i := range tools {
		fnRaw, ok := tools[i]["function"]
		if !ok || isEmptyOrNull(fnRaw) {
			continue
		}
		var fn map[string]json.RawMessage
		if err := json.Unmarshal(fnRaw, &fn); err != nil {
			continue
		}
		paramsRaw, hasParams := fn["parameters"]
		if hasParams && !isEmptyOrNull(paramsRaw) && string(paramsRaw) != "{}" {
			continue
		}
		fn["parameters"] = defaultParams
		fnBytes, err := json.Marshal(fn)
		if err != nil {
			continue
		}
		tools[i]["function"] = fnBytes
		changed = true
	}
	if !changed {
		return toolsRaw, false
	}
	b, err := json.Marshal(tools)
	if err != nil {
		return toolsRaw, false
	}
	return b, true
}

// normalizeCustomTools rewrites custom tools spelled the Responses way into the
// shape chat/completions requires. Clients that target GPT-5 models (Cursor)
// declare them flat, with name/description/format alongside "type" and the
// grammar fields alongside format.type; chat/completions demands the payload
// nested under "custom" and the grammar under format.grammar, and rejects the
// whole request otherwise (ENG-1281). Tools already in the nested shape are
// left untouched, so this is idempotent.
func normalizeCustomTools(toolsRaw json.RawMessage) (json.RawMessage, bool) {
	if len(toolsRaw) == 0 || string(toolsRaw) == "null" {
		return toolsRaw, false
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return toolsRaw, false
	}
	changed := false
	for i := range tools {
		var kind string
		if json.Unmarshal(tools[i]["type"], &kind) != nil || kind != "custom" {
			continue
		}

		custom := map[string]json.RawMessage{}
		rewritten := false
		if nested, ok := tools[i]["custom"]; ok && !isEmptyOrNull(nested) {
			if json.Unmarshal(nested, &custom) != nil {
				continue
			}
		} else {
			for _, field := range []string{"name", "description", "format"} {
				if v, ok := tools[i][field]; ok {
					custom[field] = v
					delete(tools[i], field)
				}
			}
			if len(custom) == 0 {
				continue
			}
			rewritten = true
		}

		if format, ok := custom["format"]; ok {
			if wrapped := wrapCustomToolFormat(format); !bytes.Equal(wrapped, format) {
				custom["format"] = wrapped
				rewritten = true
			}
		}
		if !rewritten {
			continue
		}
		b, err := json.Marshal(custom)
		if err != nil {
			return toolsRaw, false
		}
		tools[i]["custom"] = b
		changed = true
	}
	if !changed {
		return toolsRaw, false
	}
	b, err := json.Marshal(tools)
	if err != nil {
		return toolsRaw, false
	}
	return b, true
}

// NormalizeGroqRequest applies OpenAI-compatible fixes plus Groq-specific
// request normalizations before calling the Groq API. It does not alter upstream
// error responses.
//
// Groq-specific normalizations:
//   - Ensures tools[].type is "function" when the tools array is present.
//   - Sets parallel_tool_calls to false when tools are used and the field is
//     omitted (reduces tool_use_failed on some Llama models).
//   - Drops assistant history messages that only contain Llama-style
//     <function=...> text without structured tool_calls (poisoned turns from
//     clients or prior failed generations).
func NormalizeGroqRequest(body []byte) []byte {
	body = NormalizeOpenAIRequest(body)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}

	changed := false

	if toolsRaw, ok := raw["tools"]; ok && len(toolsRaw) > 0 && string(toolsRaw) != "null" {
		if b, ok := normalizeToolsArrayType(toolsRaw); ok {
			raw["tools"] = b
			changed = true
		}
		if _, has := raw["parallel_tool_calls"]; !has {
			b, _ := json.Marshal(false)
			raw["parallel_tool_calls"] = b
			changed = true
		}
	}

	if msgsRaw, ok := raw["messages"]; ok {
		if b, ok := stripLlamaStyleFunctionOnlyMessages(msgsRaw); ok {
			raw["messages"] = b
			changed = true
		}
	}

	if !changed {
		return body
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

func normalizeToolsArrayType(toolsRaw json.RawMessage) (json.RawMessage, bool) {
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return toolsRaw, false
	}
	changed := false
	for i := range tools {
		typeRaw, hasType := tools[i]["type"]
		if !hasType || isEmptyOrNull(typeRaw) {
			b, _ := json.Marshal("function")
			tools[i]["type"] = b
			changed = true
		}
	}
	if !changed {
		return toolsRaw, false
	}
	b, err := json.Marshal(tools)
	if err != nil {
		return toolsRaw, false
	}
	return b, true
}

func stripLlamaStyleFunctionOnlyMessages(msgsRaw json.RawMessage) (json.RawMessage, bool) {
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(msgsRaw, &msgs); err != nil {
		return msgsRaw, false
	}
	filtered := make([]map[string]json.RawMessage, 0, len(msgs))
	changed := false
	for _, m := range msgs {
		role := messageRole(m)
		if role == "assistant" && hasLlamaStyleFunctionContent(m) && !messageHasToolCalls(m) {
			changed = true
			continue
		}
		filtered = append(filtered, m)
	}
	if !changed {
		return msgsRaw, false
	}
	b, err := json.Marshal(filtered)
	if err != nil {
		return msgsRaw, false
	}
	return b, true
}

func messageRole(m map[string]json.RawMessage) string {
	raw, ok := m["role"]
	if !ok {
		return ""
	}
	var role string
	if err := json.Unmarshal(raw, &role); err != nil {
		return ""
	}
	return role
}

func messageHasToolCalls(m map[string]json.RawMessage) bool {
	raw, ok := m["tool_calls"]
	if !ok || isEmptyOrNull(raw) {
		return false
	}
	var tcs []json.RawMessage
	if err := json.Unmarshal(raw, &tcs); err != nil {
		return false
	}
	return len(tcs) > 0
}

func hasLlamaStyleFunctionContent(m map[string]json.RawMessage) bool {
	raw, ok := m["content"]
	if !ok || isEmptyOrNull(raw) {
		return false
	}
	var content string
	if err := json.Unmarshal(raw, &content); err != nil {
		return false
	}
	return strings.Contains(content, "<function=")
}

// NormalizeRequestForProvider applies provider-specific request fixes before an
// upstream call. Groq uses NormalizeGroqRequest; other OpenAI-wire targets use
// NormalizeOpenAIRequest when applicable.
func NormalizeRequestForProvider(providerName string, targetFormat Format, body []byte) []byte {
	if providerName == provider.Groq {
		return NormalizeGroqRequest(body)
	}
	if IsSameWireFormat(targetFormat, FormatOpenAI) {
		return NormalizeOpenAIRequest(body)
	}
	return body
}

// isEmptyOrNull returns true for nil, empty, `null`, or `""` JSON values.
func isEmptyOrNull(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	s := string(raw)
	return s == "null" || s == `""`
}
