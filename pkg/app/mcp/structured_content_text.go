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

package mcp

import (
	"bytes"
	"encoding/json"
)

// withStructuredContentText appends a text block holding the compact JSON of
// structuredContent when a tools/call result has structured content and no text
// item. MCP 2025-06-18 asks for that block so a client that only reads content
// still sees the payload. Results that already contain a text item are returned
// as they arrived.
//
// Callers run this on the result response plugins left behind. The text is that
// structuredContent, so a redaction applied to the object is what the text
// carries. isError is not read and not written: an error result stays an error.
func withStructuredContentText(result json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil || fields == nil {
		return result
	}
	structured, ok := fields["structuredContent"]
	if !ok || isJSONNull(structured) {
		return result
	}
	compact, ok := compactJSON(structured)
	if !ok {
		return result
	}
	if contentHasTextItem(fields["content"]) {
		return result
	}
	content, ok := appendTextContent(fields["content"], string(compact))
	if !ok {
		return result
	}
	fields["content"] = content
	out, err := json.Marshal(fields)
	if err != nil {
		return result
	}
	return out
}

func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// compactJSON is the structured value with insignificant whitespace removed
// and its key order left as it arrived. Re-encoding through a map would sort
// the keys and hand the client a different document.
func compactJSON(raw json.RawMessage) ([]byte, bool) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, bytes.TrimSpace(raw)); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func contentHasTextItem(raw json.RawMessage) bool {
	blocks, ok := contentBlockList(raw)
	if !ok {
		return false
	}
	for _, block := range blocks {
		var item struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(block, &item); err != nil {
			continue
		}
		if item.Type == "text" {
			return true
		}
	}
	return false
}

// contentBlockList reports the content array. Missing and null content are an
// empty array the caller can append to. Anything that is not an array is not
// one: appending would have to replace it.
func contentBlockList(raw json.RawMessage) ([]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, true
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(trimmed, &blocks); err != nil {
		return nil, false
	}
	return blocks, true
}

func appendTextContent(content json.RawMessage, text string) (json.RawMessage, bool) {
	blocks, ok := contentBlockList(content)
	if !ok {
		return nil, false
	}
	block, err := json.Marshal(struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{Type: "text", Text: text})
	if err != nil {
		return nil, false
	}
	blocks = append(blocks, block)
	out, err := json.Marshal(blocks)
	if err != nil {
		return nil, false
	}
	return out, true
}
