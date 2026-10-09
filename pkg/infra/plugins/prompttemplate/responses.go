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

package prompttemplate

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	reasonInstructionsUnreadable   = "instructions_unreadable"
	reasonInputUnreadable          = "input_unreadable"
	reasonRoleUnsupportedResponses = "role_not_supported_on_responses"
)

// The Responses shape is edited as raw fields only. The system prompt is the
// top-level instructions string; the conversation is input, a string or a list
// of items (adapter.decodeResponsesInput). The adapter reads any item with a
// role as a message, and folds system and developer items into the system
// prompt, so system text is always written to instructions instead.

func (rb *requestBody) injectResponses(mode onExistingSystem, role, content string) (bool, string) {
	switch role {
	case roleSystem:
		return rb.injectInstructions(mode, content)
	case roleUser, "assistant", "developer":
		return rb.prependResponsesItem(role, content)
	default:
		return false, reasonRoleUnsupportedResponses
	}
}

func (rb *requestBody) injectInstructions(mode onExistingSystem, content string) (bool, string) {
	existing := ""
	if raw, ok := rb.fields["instructions"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &existing); err != nil {
			return false, reasonInstructionsUnreadable
		}
	}
	encoded, err := json.Marshal(mergeSystem(mode, existing, content))
	if err != nil {
		return false, reasonEncodeFailed
	}
	rb.fields["instructions"] = encoded
	rb.rawDirty = true
	return true, ""
}

// responsesInput returns the input as items. A string becomes the single user
// item it stands for; absent or null is no items. ok is false for any other
// value.
func (rb *requestBody) responsesInput() (items []json.RawMessage, ok bool) {
	raw, present := rb.fields["input"]
	if !present || isJSONNull(raw) {
		return nil, true
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		item, err := responsesItem("user", text)
		if err != nil {
			return nil, false
		}
		return []json.RawMessage{item}, true
	}
	if json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	return items, true
}

func responsesItem(role, text string) (json.RawMessage, error) {
	item, err := json.Marshal(map[string]string{"type": "message", "role": role, "content": text})
	if err != nil {
		return nil, fmt.Errorf("encode input item: %w", err)
	}
	return item, nil
}

func (rb *requestBody) setResponsesInput(items []json.RawMessage) error {
	if items == nil {
		items = []json.RawMessage{}
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("encode input: %w", err)
	}
	rb.fields["input"] = encoded
	rb.rawDirty = true
	return nil
}

func (rb *requestBody) prependResponsesItem(role, content string) (bool, string) {
	items, ok := rb.responsesInput()
	if !ok {
		return false, reasonInputUnreadable
	}
	item, err := responsesItem(role, content)
	if err != nil {
		return false, reasonEncodeFailed
	}
	next := make([]json.RawMessage, 0)
	next = append(next, item)
	next = append(next, items...)
	if err := rb.setResponsesInput(next); err != nil {
		return false, reasonEncodeFailed
	}
	return true, ""
}

// findResponsesReferences scans input when it is a string, and the text of
// message items: string content, or any content part with a string text (text,
// input_text, output_text), as decodeOpenAIParts reads them, plus a bare
// input_text item. A part whose text is not a string is skipped on its own.
func (rb *requestBody) findResponsesReferences() []templateRef {
	raw, ok := rb.fields["input"]
	if !ok {
		return nil
	}
	if text, ok := rawString(raw); ok {
		return scanReferences(text)
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil
	}
	var refs []templateRef
	for _, rawItem := range items {
		var item struct {
			Role    string          `json:"role"`
			Type    string          `json:"type"`
			Text    json.RawMessage `json:"text"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(rawItem, &item) != nil {
			continue
		}
		// The adapter reads an item with a role through its content, and the
		// text of an input_text item only when it has no role
		// (appendResponsesInputItem).
		if item.Role == "" {
			if item.Type == "input_text" {
				if text, ok := rawString(item.Text); ok {
					refs = append(refs, scanReferences(text)...)
				}
			}
			continue
		}
		if text, ok := rawString(item.Content); ok {
			refs = append(refs, scanReferences(text)...)
			continue
		}
		var parts []json.RawMessage
		if json.Unmarshal(item.Content, &parts) != nil {
			continue
		}
		for _, rawPart := range parts {
			var part struct {
				Text json.RawMessage `json:"text"`
			}
			if json.Unmarshal(rawPart, &part) != nil {
				continue
			}
			if text, ok := rawString(part.Text); ok {
				refs = append(refs, scanReferences(text)...)
			}
		}
	}
	return refs
}

func rawString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func (rb *requestBody) responsesTurnCount() int {
	raw, ok := rb.fields["input"]
	if !ok || isJSONNull(raw) {
		return 0
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
		return 1
	}
	items, _ := rb.responsesInput()
	return len(items)
}

// replaceResponsesInput is replaceMessages for a Responses body. A plain string
// becomes the input string; a messages fragment becomes message items, with its
// system text merged into instructions. Roles other than assistant and
// developer become user items.
func (rb *requestBody) replaceResponsesInput(rendered string) error {
	frag, err := parseFragment(rendered)
	if err != nil {
		return err
	}
	if frag.isPlain {
		encoded, err := json.Marshal(frag.plain)
		if err != nil {
			return fmt.Errorf("encode rendered input: %w", err)
		}
		rb.fields["input"] = encoded
		rb.rawDirty = true
		return nil
	}
	items := make([]json.RawMessage, 0, len(frag.turns))
	for _, t := range frag.turns {
		role := "user"
		if t.role == "assistant" || t.role == "developer" {
			role = t.role
		}
		item, err := responsesItem(role, joinTexts(t.texts))
		if err != nil {
			return err
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return &fragmentError{msg: "rendered template has no conversation turns"}
	}
	if err := rb.setResponsesInput(items); err != nil {
		return err
	}
	if frag.system != "" {
		if applied, reason := rb.injectInstructions(onExistingMerge, frag.system); !applied {
			return foldError("instructions", reason)
		}
	}
	return nil
}
