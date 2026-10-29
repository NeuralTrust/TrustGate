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
	"strconv"
	"strings"
)

// mcpTransformedRequest lifts the masked tools/call arguments out of the
// envelope TrustGuard echoes back for protocol=mcp — the same
// {jsonrpc,id,method,params} shape mcpToolsCallPayload sent, with the detected
// spans replaced. Nothing has to be re-split, so the structure survives exactly
// as the detector left it.
//
// The tool name comes from the original call, never from the payload: routing
// is the gateway's decision and must not be steered by a masking outcome.
func mcpTransformedRequest(payload map[string]any, name string) ([]byte, bool) {
	params, ok := payload["params"].(map[string]any)
	if !ok {
		return nil, false
	}
	arguments, ok := params["arguments"]
	if !ok {
		return nil, false
	}
	raw, err := json.Marshal(arguments)
	if err != nil {
		return nil, false
	}
	out, err := json.Marshal(mcpToolCall{Name: name, Arguments: raw})
	if err != nil {
		return nil, false
	}
	return out, true
}

// mcpTransformedResult lifts the masked CallToolResult out of the JSON-RPC
// result envelope mcpToolsResultPayload built from original.
//
// structuredContent is rebuilt from the original tree with only its string
// values taken from the mask, so keys and scalars stay exactly as the tool sent
// them; a mask that changed either, or whose probe shows a flagged key or
// scalar, is refused and the caller blocks instead.
func mcpTransformedResult(payload map[string]any, original []byte) ([]byte, bool) {
	result, ok := payload["result"].(map[string]any)
	if !ok {
		return nil, false
	}
	var decoded any
	if err := decodeJSON(string(original), &decoded); err != nil {
		return nil, false
	}
	orig, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}
	if !stripStructuredProbe(result, orig) {
		return nil, false
	}
	origStructured, hadStructured := orig["structuredContent"]
	maskedStructured, hasStructured := result["structuredContent"]
	if hadStructured != hasStructured {
		return nil, false
	}
	if hadStructured {
		merged, ok := mergeStructuredStrings(origStructured, maskedStructured)
		if !ok {
			return nil, false
		}
		result["structuredContent"] = merged
	}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, false
	}
	return out, true
}

// stripStructuredProbe removes the probe block mcpToolsResultPayload appended
// and reports whether every key and scalar it listed came back unmasked.
func stripStructuredProbe(result, orig map[string]any) bool {
	_, parts, ok := structuredProbe(orig)
	if !ok {
		return true
	}
	origBlocks, _ := orig["content"].([]any)
	blocks, ok := result["content"].([]any)
	if !ok || len(blocks) != len(origBlocks)+1 {
		return false
	}
	probe, ok := blocks[len(blocks)-1].(map[string]any)
	if !ok {
		return false
	}
	text, ok := probe["text"].(string)
	if !ok {
		return false
	}
	texts := make([]string, len(parts))
	for i, part := range parts {
		texts[i] = part.text
	}
	masked, ok := redistribute(text, texts)
	if !ok {
		return false
	}
	for i, part := range parts {
		if !part.rewritable && masked[i] != part.text {
			return false
		}
	}
	if content, had := orig["content"]; !had {
		delete(result, "content")
	} else if _, isArray := content.([]any); !isArray {
		result["content"] = content
	} else {
		result["content"] = blocks[:len(blocks)-1]
	}
	return true
}

// mergeStructuredStrings returns orig with its string values replaced by their
// masked counterparts. masked must have the same shape, keys and scalar values
// as orig. Numbers are compared by value because TrustGuard's response is not
// decoded with UseNumber; the original json.Number is what is written back, so
// integers past 2^53 keep their digits.
func mergeStructuredStrings(orig, masked any) (any, bool) {
	switch o := orig.(type) {
	case map[string]any:
		m, ok := masked.(map[string]any)
		if !ok || len(m) != len(o) {
			return nil, false
		}
		for k, ov := range o {
			mv, ok := m[k]
			if !ok {
				return nil, false
			}
			merged, ok := mergeStructuredStrings(ov, mv)
			if !ok {
				return nil, false
			}
			o[k] = merged
		}
		return o, true
	case []any:
		m, ok := masked.([]any)
		if !ok || len(m) != len(o) {
			return nil, false
		}
		for i := range o {
			merged, ok := mergeStructuredStrings(o[i], m[i])
			if !ok {
				return nil, false
			}
			o[i] = merged
		}
		return o, true
	case string:
		m, ok := masked.(string)
		return m, ok
	case json.Number:
		return o, sameNumber(o, masked)
	case bool:
		m, ok := masked.(bool)
		return o, ok && m == o
	case nil:
		return nil, masked == nil
	default:
		return nil, false
	}
}

func sameNumber(orig json.Number, masked any) bool {
	switch m := masked.(type) {
	case json.Number:
		return m.String() == orig.String()
	case float64:
		f, err := orig.Float64()
		return err == nil && f == m
	default:
		return false
	}
}

// rewriteMCPRequest writes TrustGuard's masked text back into the tools/call
// arguments, mirroring how the LLM path writes it back into the message
// segments. The parts are rebuilt exactly as mcpInputText collected them so the
// masked text maps onto the inspected payload; anything ambiguous or
// unrewritable fails, and the caller then blocks rather than forwarding
// unmasked data.
func rewriteMCPRequest(body []byte, masked string) ([]byte, bool) {
	var call mcpToolCall
	if err := json.Unmarshal(body, &call); err != nil {
		return nil, false
	}
	// Arguments that are not valid JSON are inspected as one raw blob; there is
	// no structure to write back into, so refuse instead of guessing.
	var decoded any
	if len(call.Arguments) == 0 || json.Unmarshal(call.Arguments, &decoded) != nil {
		return nil, false
	}

	parts := make([]string, 0, 4)
	name := strings.TrimSpace(call.Name)
	if name != "" {
		parts = append(parts, name)
	}
	leaves := collectStringValues(decoded, nil)
	if len(leaves) == 0 {
		return nil, false
	}
	parts = append(parts, leaves...)

	maskedParts, ok := redistribute(masked, parts)
	if !ok {
		return nil, false
	}
	if name != "" {
		// The tool name was inspected but is never rewritten: routing is the
		// gateway's decision, not a masking outcome.
		maskedParts = maskedParts[1:]
	}

	idx := 0
	patched, ok := replaceStringValues(decoded, maskedParts, &idx)
	if !ok || idx != len(maskedParts) {
		return nil, false
	}
	arguments, err := json.Marshal(patched)
	if err != nil {
		return nil, false
	}
	out, err := json.Marshal(mcpToolCall{Name: call.Name, Arguments: arguments})
	if err != nil {
		return nil, false
	}
	return out, true
}

// replaceArgumentStrings walks the arguments tree in the same order
// collectStrings did — maps by sorted key, arrays in order, blank strings
// skipped — replacing each inspected string leaf with its masked counterpart.
// Map keys and non-string scalar leaves are inspected but cannot safely be
// rewritten. If TrustGuard changes either, the payload is unrewritable and the
// caller blocks rather than forwarding the unmasked data.
func replaceArgumentStrings(value any, masked []string, idx *int) (any, bool) {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return v, true
		}
		if *idx >= len(masked) {
			return nil, false
		}
		out := masked[*idx]
		*idx++
		return out, true
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.TrimSpace(k) != "" {
				if !consumeUnrewritablePart(k, masked, idx) {
					return nil, false
				}
			}
			patched, ok := replaceArgumentStrings(v[k], masked, idx)
			if !ok {
				return nil, false
			}
			v[k] = patched
		}
		return v, true
	case []any:
		for i := range v {
			patched, ok := replaceArgumentStrings(v[i], masked, idx)
			if !ok {
				return nil, false
			}
			v[i] = patched
		}
		return v, true
	case nil:
		return value, consumeUnrewritablePart("null", masked, idx)
	case bool:
		return value, consumeUnrewritablePart(strconv.FormatBool(v), masked, idx)
	case json.Number:
		return value, consumeUnrewritablePart(v.String(), masked, idx)
	default:
		return value, true
	}
}

func replaceStringValues(value any, masked []string, idx *int) (any, bool) {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return v, true
		}
		if *idx >= len(masked) {
			return nil, false
		}
		out := masked[*idx]
		*idx++
		return out, true
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			patched, ok := replaceStringValues(v[k], masked, idx)
			if !ok {
				return nil, false
			}
			v[k] = patched
		}
		return v, true
	case []any:
		for i := range v {
			patched, ok := replaceStringValues(v[i], masked, idx)
			if !ok {
				return nil, false
			}
			v[i] = patched
		}
		return v, true
	default:
		return value, true
	}
}

func consumeUnrewritablePart(original string, masked []string, idx *int) bool {
	if *idx >= len(masked) || masked[*idx] != original {
		return false
	}
	*idx++
	return true
}

// rewriteMCPResponse writes the masked text back into a CallToolResult: first the
// content blocks that carry text — text blocks and embedded resources alike —
// then the inspectable parts of structuredContent, in the exact order
// mcpOutputText collected them. The result is patched in place on a generic
// decode rather than re-encoded from a typed struct, so fields the gateway does
// not model (_meta, annotations) survive the rewrite.
//
// This is the string-payload fallback; the structured applyPayload path
// (mcpTransformedResult) is tried first and lifts the whole masked envelope. It
// still has to cover structuredContent so a result whose only inspectable data
// lives there is masked here rather than degrading to a block.
func rewriteMCPResponse(body []byte, masked string) ([]byte, bool) {
	var decoded any
	if err := decodeJSON(string(body), &decoded); err != nil {
		return nil, false
	}
	generic, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}

	// Same selection as mcpOutputText: text blocks and embedded resources with
	// non-blank text, in content order.
	holders := make([]map[string]any, 0)
	parts := make([]string, 0)
	if blocks, ok := generic["content"].([]any); ok {
		for _, raw := range blocks {
			block, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			holder, text, ok := blockTextHolder(block)
			if !ok || strings.TrimSpace(text) == "" {
				continue
			}
			holders = append(holders, holder)
			parts = append(parts, text)
		}
	}

	// Then structuredContent map keys, string leaves, and scalar leaves in
	// sorted-key order, matching flattenStructuredContent so the masked halves
	// line up. A top-level null contributes nothing and is left untouched.
	structured, hasStructured := generic["structuredContent"]
	var structuredLeaves int
	if hasStructured {
		leaves := collectStrings(structured, nil)
		structuredLeaves = len(leaves)
		parts = append(parts, leaves...)
	}
	if len(parts) == 0 {
		return nil, false
	}

	maskedParts, ok := redistribute(masked, parts)
	if !ok {
		return nil, false
	}
	for i, holder := range holders {
		holder["text"] = maskedParts[i]
	}
	if structuredLeaves > 0 {
		idx := 0
		patched, ok := replaceArgumentStrings(structured, maskedParts[len(holders):], &idx)
		if !ok || idx != structuredLeaves {
			return nil, false
		}
		generic["structuredContent"] = patched
	}
	out, err := json.Marshal(generic)
	if err != nil {
		return nil, false
	}
	return out, true
}

// blockTextHolder returns the map that owns the inspectable "text" key of a
// content block, the text itself, and whether the block contributes any.
//
// It is the write-side mirror of blockInspectableText in mcp.go: the block
// itself for a text block, the embedded resource object for a resource block.
// Returning the holder rather than the text alone is what lets the masked value
// be written back into resource.text without the caller knowing which shape it
// is looking at. The two functions must stay in step — a block inspected here
// and not there, or vice versa, misaligns redistribute.
func blockTextHolder(block map[string]any) (map[string]any, string, bool) {
	kind, _ := block["type"].(string)
	if kind == "resource" {
		resource, ok := block["resource"].(map[string]any)
		if !ok {
			return nil, "", false
		}
		text, ok := resource["text"].(string)
		if !ok {
			return nil, "", false
		}
		return resource, text, true
	}
	// A blank type is a text block when it carries text, matching blockIsText.
	if kind != "" && kind != "text" {
		return nil, "", false
	}
	text, ok := block["text"].(string)
	if !ok {
		return nil, "", false
	}
	return block, text, true
}

// mcpToolName reads the tool name from the gateway's tools/call body.
func mcpToolName(body []byte) string {
	var call mcpToolCall
	if err := json.Unmarshal(body, &call); err != nil {
		return ""
	}
	return call.Name
}
