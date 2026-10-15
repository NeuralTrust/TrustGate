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
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// BedrockFrameText is the text a frame carries as the view reads it: what a
// guardrail is shown for it, every string of the chunk included.
func BedrockFrameText(frame []byte) string {
	return bedrockFrameText(frame, true)
}

// BedrockFrameModelledText is BedrockFrameText without the strings the view
// adds from fields no family decoder models. What it returns is text the model
// wrote in a delta; the difference from BedrockFrameText is plumbing that only
// rides along in the view.
func BedrockFrameModelledText(frame []byte) string {
	return bedrockFrameText(frame, false)
}

func bedrockFrameText(frame []byte, leftover bool) string {
	a := &BedrockNativeAdapter{}
	var text string
	for _, line := range BedrockFrameView(frame) {
		payload, ok := bytes.CutPrefix(line, []byte("data: "))
		if !ok {
			continue
		}
		chunk, err := a.decodeStreamChunk(payload, leftover)
		if err != nil || chunk == nil {
			continue
		}
		text += chunk.Delta + chunk.ReasoningDelta
	}
	return text
}

// BedrockFrameHolds reports whether text is anywhere in what the frame says,
// decoded: every string of its payload JSON and, for an InvokeModel chunk, of the
// JSON it carries in base64, with JSON escapes undone even inside a string that
// holds JSON of its own, as a tool input fragment does. Bedrock's random "p"
// padding field is skipped. It does not depend on the view, so text in a field
// the view leaves out is found too, and an escaped "\u0040" is found as "@".
// A fragment of a value split across frames is not found here: the stream guard
// checks the accumulated tool input for that. A frame that cannot be decoded
// holds the text, since it cannot be shown to be clean.
func BedrockFrameHolds(frame []byte, text string) bool {
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	if err != nil {
		return true
	}
	tree, ok := decodeJSONTree(msg.Payload)
	if !ok {
		return bytes.Contains(msg.Payload, []byte(text))
	}
	holder, isMap := tree.(map[string]any)
	if headerString(msg.Headers, eventHeaderEventType) == eventTypeInvokeChunk && isMap {
		encoded, _ := holder["bytes"].(string)
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return true
		}
		inner, ok := decodeJSONTree(raw)
		if !ok {
			return bytes.Contains(raw, []byte(text))
		}
		return treeHolds(inner, text, true)
	}
	return treeHolds(tree, text, true)
}

func treeHolds(v any, text string, top bool) bool {
	switch t := v.(type) {
	case string:
		return StringHolds(t, text)
	case []any:
		for _, item := range t {
			if treeHolds(item, text, false) {
				return true
			}
		}
	case map[string]any:
		for k, val := range t {
			if top && k == "p" {
				continue
			}
			if StringHolds(k, text) || treeHolds(val, text, false) {
				return true
			}
		}
	}
	return false
}

// StringHolds reports whether s holds text, as it is and with the JSON escapes
// in it undone, which is how a tool input fragment, a JSON document carried in a
// string, hides a character.
func StringHolds(s, text string) bool {
	if text == "" {
		return false
	}
	for range 3 {
		if strings.Contains(s, text) {
			return true
		}
		next := LooseJSONUnescape(s)
		if next == s {
			return false
		}
		s = next
	}
	return strings.Contains(s, text)
}

// LooseJSONUnescape undoes the escapes of a JSON string literal in text that is
// not a whole literal, such as a fragment of a streamed tool input.
func LooseJSONUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case '"', '\\', '/':
			sb.WriteByte(s[i])
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case 'r':
			sb.WriteByte('\r')
		case 'b':
			sb.WriteByte('\b')
		case 'f':
			sb.WriteByte('\f')
		case 'u':
			code, ok := hex4([]byte(s), i+1)
			if !ok {
				sb.WriteString(`\u`)
				continue
			}
			i += 4
			r := rune(code)
			if r >= 0xD800 && r <= 0xDBFF && i+6 < len(s) && s[i+1] == '\\' && s[i+2] == 'u' {
				if low, ok := hex4([]byte(s), i+3); ok && low >= 0xDC00 && low <= 0xDFFF {
					r = 0x10000 + (r-0xD800)<<10 + rune(low) - 0xDC00
					i += 6
				}
			}
			sb.WriteRune(r)
		default:
			sb.WriteByte('\\')
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// RewriteBedrockFrameText returns the frame with the one string equal to
// oldText replaced by newText. Only this frame is re-encoded: its headers are
// kept as they were, every other field of the payload keeps its value (number
// literals included, though the keys of the payload may come out in another
// order), and the prelude, length and both checksums are valid for the new
// payload. Frames the mask does not touch are never passed through here. A ConverseStream event holds the text in
// its payload; an InvokeModel chunk holds the model's own JSON, base64 encoded.
// ok is false when the frame is not an event, holds no such string, or cannot be
// rebuilt, and the caller must not release it.
func RewriteBedrockFrameText(frame []byte, oldText, newText string) ([]byte, bool) {
	if oldText == "" {
		return nil, false
	}
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	if err != nil || headerString(msg.Headers, eventHeaderMessageType) != eventMessageTypeEvent {
		return nil, false
	}
	payload, ok := rewritePayload(msg.Payload, headerString(msg.Headers, eventHeaderEventType) == eventTypeInvokeChunk, oldText, newText)
	if !ok {
		return nil, false
	}
	var out bytes.Buffer
	if err := eventstream.NewEncoder().Encode(&out, eventstream.Message{Headers: msg.Headers, Payload: payload}); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}

func rewritePayload(payload []byte, invokeChunk bool, oldText, newText string) ([]byte, bool) {
	tree, ok := decodeJSONTree(payload)
	if !ok {
		return nil, false
	}
	if !invokeChunk {
		if !replaceLeaf(tree, oldText, newText) {
			return nil, false
		}
		out, err := marshalNoEscape(tree)
		return out, err == nil
	}
	holder, isMap := tree.(map[string]any)
	if !isMap {
		return nil, false
	}
	encoded, isString := holder["bytes"].(string)
	if !isString {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	inner, ok := decodeJSONTree(raw)
	if !ok || !replaceLeaf(inner, oldText, newText) {
		return nil, false
	}
	rewritten, err := marshalNoEscape(inner)
	if err != nil {
		return nil, false
	}
	holder["bytes"] = base64.StdEncoding.EncodeToString(rewritten)
	out, err := marshalNoEscape(holder)
	return out, err == nil
}

func decodeJSONTree(raw []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, false
	}
	return tree, true
}

func replaceLeaf(v any, oldText, newText string) bool {
	switch t := v.(type) {
	case []any:
		for i := range t {
			if s, ok := t[i].(string); ok && s == oldText {
				t[i] = newText
				return true
			}
			if replaceLeaf(t[i], oldText, newText) {
				return true
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s, ok := t[k].(string); ok && s == oldText {
				t[k] = newText
				return true
			}
			if replaceLeaf(t[k], oldText, newText) {
				return true
			}
		}
	}
	return false
}
