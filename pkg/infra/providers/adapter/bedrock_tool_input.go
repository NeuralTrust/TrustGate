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
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// NormalizeToolInput writes every string of a tool input, a JSON document, the
// way a policy reads text: with its escapes undone, so that "@" is the "@"
// it stands for. Nothing else changes: keys, numbers, structure and spacing are
// as they were. ok is false when input is not valid JSON, or when a string in it
// does not survive being read and written back exactly (an unpaired surrogate).
func NormalizeToolInput(input string) (string, bool) {
	// A lone surrogate escape or a byte that is not UTF-8 would be read as U+FFFD
	// and written back as that, changing a string nobody masked: such an input is
	// not normalised, and a mask on it is refused.
	if HasInvalidText([]byte(input)) {
		return input, false
	}
	root, ok := parseJSON([]byte(input))
	if !ok {
		return input, false
	}
	var strs []*jnode
	collectStringNodes(root, &strs)
	var sb strings.Builder
	cur := 0
	for _, n := range strs {
		quoted, err := marshalNoEscape(n.str)
		if err != nil {
			return input, false
		}
		sb.WriteString(input[cur:n.start])
		sb.Write(quoted)
		cur = n.end
	}
	sb.WriteString(input[cur:])
	return sb.String(), true
}

func collectStringNodes(n *jnode, out *[]*jnode) {
	switch n.kind {
	case 's':
		*out = append(*out, n)
	case 'a', 'o':
		for _, v := range n.vals {
			collectStringNodes(v, out)
		}
	}
}

// MaskToolInput carries a mask a policy made on a tool input over onto it. The
// replacements are read off the input and the text the policy handed back, and
// each must fall inside one string value: a replacement in a key, a number or a
// literal is not a mask of text, and ok is false. The replacement is written as
// the content of a JSON string, without HTML escaping, so the result is valid
// JSON whatever the policy wrote, and it must have the same structure as the
// input: the same keys, the same numbers, the same nesting. A removed text of
// three characters or more must not remain in the result, escapes undone; a
// shorter one is only ever changed where the policy changed it.
func MaskToolInput(input, masked string) (string, bool) {
	if HasInvalidText([]byte(input)) {
		return "", false
	}
	root, ok := parseJSON([]byte(input))
	if !ok {
		return "", false
	}
	hunks, ok := diffText(input, masked)
	if !ok || len(hunks) == 0 {
		return "", false
	}
	var strs []*jnode
	collectStringNodes(root, &strs)
	inString := func(start, end int) bool {
		for _, n := range strs {
			if start >= n.start+1 && end <= n.end-1 {
				return true
			}
		}
		return false
	}
	var (
		sb      strings.Builder
		removed []string
		cur     int
	)
	for _, h := range hunks {
		from := input[h.start:h.end]
		if strings.TrimSpace(from) == "" || !inString(h.start, h.end) {
			return "", false
		}
		quoted, err := marshalNoEscape(h.insert)
		if err != nil {
			return "", false
		}
		sb.WriteString(input[cur:h.start])
		sb.Write(quoted[1 : len(quoted)-1])
		cur = h.end
		removed = append(removed, from)
	}
	sb.WriteString(input[cur:])
	out := sb.String()
	got, ok := parseJSON([]byte(out))
	if !ok || !sameJSONStructure(root, got) {
		return "", false
	}
	for _, from := range removed {
		if len(from) >= minGlobalMaskLen && StringHolds(out, from) {
			return "", false
		}
	}
	return out, true
}

func sameJSONStructure(a, b *jnode) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case 'x':
		return a.raw == b.raw
	case 'a', 'o':
		if len(a.vals) != len(b.vals) || strings.Join(a.keys, "\x00") != strings.Join(b.keys, "\x00") {
			return false
		}
		for i := range a.vals {
			if !sameJSONStructure(a.vals[i], b.vals[i]) {
				return false
			}
		}
	}
	return true
}

// toolInputHolder finds the string a frame carries a fragment of tool input in:
// a ConverseStream contentBlockDelta holds it at delta.toolUse.input, and the
// model's own events of an InvokeModel chunk at delta.partial_json when the
// delta is an input_json_delta.
func toolInputHolder(tree any, invokeChunk bool) (map[string]any, string, bool) {
	root, ok := tree.(map[string]any)
	if !ok {
		return nil, "", false
	}
	delta, ok := root["delta"].(map[string]any)
	if !ok {
		return nil, "", false
	}
	if invokeChunk {
		if stringOf(delta, "type") != "input_json_delta" {
			return nil, "", false
		}
		if _, ok := delta["partial_json"].(string); !ok {
			return nil, "", false
		}
		return delta, "partial_json", true
	}
	use, ok := delta["toolUse"].(map[string]any)
	if !ok {
		return nil, "", false
	}
	if _, ok := use["input"].(string); !ok {
		return nil, "", false
	}
	return use, "input", true
}

// BedrockFrameToolInput returns the fragment of tool input a frame carries.
func BedrockFrameToolInput(frame []byte) (string, bool) {
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	if err != nil || headerString(msg.Headers, eventHeaderMessageType) != eventMessageTypeEvent {
		return "", false
	}
	invoke := headerString(msg.Headers, eventHeaderEventType) == eventTypeInvokeChunk
	tree, ok := decodeJSONTree(msg.Payload)
	if !ok {
		return "", false
	}
	if invoke {
		inner, ok := invokeInner(tree)
		if !ok {
			return "", false
		}
		tree = inner
	}
	holder, key, ok := toolInputHolder(tree, invoke)
	if !ok {
		return "", false
	}
	return holder[key].(string), true
}

// RewriteBedrockFrameToolInput returns the frame with the fragment of tool input
// it carries replaced by input, with its headers and every other field as they
// were and a prelude, length and checksums valid for the new payload. ok is false
// when the frame carries no tool input.
func RewriteBedrockFrameToolInput(frame []byte, input string) ([]byte, bool) {
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	if err != nil || headerString(msg.Headers, eventHeaderMessageType) != eventMessageTypeEvent {
		return nil, false
	}
	invoke := headerString(msg.Headers, eventHeaderEventType) == eventTypeInvokeChunk
	tree, ok := decodeJSONTree(msg.Payload)
	if !ok {
		return nil, false
	}
	var payload []byte
	if invoke {
		inner, ok := invokeInner(tree)
		if !ok {
			return nil, false
		}
		holder, key, ok := toolInputHolder(inner, true)
		if !ok {
			return nil, false
		}
		holder[key] = input
		rewritten, err := marshalNoEscape(inner)
		if err != nil {
			return nil, false
		}
		tree.(map[string]any)["bytes"] = base64.StdEncoding.EncodeToString(rewritten)
		if payload, err = marshalNoEscape(tree); err != nil {
			return nil, false
		}
	} else {
		holder, key, ok := toolInputHolder(tree, false)
		if !ok {
			return nil, false
		}
		holder[key] = input
		if payload, err = marshalNoEscape(tree); err != nil {
			return nil, false
		}
	}
	var out bytes.Buffer
	if err := eventstream.NewEncoder().Encode(&out, eventstream.Message{Headers: msg.Headers, Payload: payload}); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}

func invokeInner(tree any) (any, bool) {
	holder, ok := tree.(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, ok := holder["bytes"].(string)
	if !ok {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	return decodeJSONTree(raw)
}
