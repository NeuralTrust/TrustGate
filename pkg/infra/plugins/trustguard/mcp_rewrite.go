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
// result envelope mcpToolsResultPayload sent.
func mcpTransformedResult(payload map[string]any) ([]byte, bool) {
	result, ok := payload["result"]
	if !ok {
		return nil, false
	}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, false
	}
	return out, true
}

// rewriteMCPRequest writes TrustGuard's masked text back into the tools/call
// arguments, mirroring how the LLM path writes it back into the message
// segments. The parts are rebuilt exactly as mcpInputText collected them so the
// masked text maps onto the values that were inspected; anything ambiguous
// fails, and the caller then blocks rather than forwarding unmasked data.
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
	leaves := collectStrings(decoded, nil)
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
	patched, ok := replaceArgumentStrings(decoded, maskedParts, &idx)
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
// skipped — replacing each inspected leaf with its masked counterpart.
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
	default:
		return value, true
	}
}

// rewriteMCPResponse writes the masked text back into a CallToolResult: first the
// content blocks that carry text — text blocks and embedded resources alike —
// then the string leaves of structuredContent, in the exact order mcpOutputText
// collected them. The result is patched in place on a generic
// decode rather than re-encoded from a typed struct, so fields the gateway does
// not model (_meta, annotations) survive the rewrite.
//
// This is the string-payload fallback; the structured applyPayload path
// (mcpTransformedResult) is tried first and lifts the whole masked envelope. It
// still has to cover structuredContent so a result whose only inspectable data
// lives there is masked here rather than degrading to a block.
func rewriteMCPResponse(body []byte, masked string) ([]byte, bool) {
	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
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

	// Then structuredContent string leaves, sorted-key order, matching
	// flattenArgumentStrings/collectStrings so the masked halves line up.
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
