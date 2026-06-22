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

const roleSystem = "system"

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type requestBody struct {
	fields         map[string]json.RawMessage
	system         string
	hasSystem      bool
	systemDirty    bool
	messages       []json.RawMessage
	hasMessages    bool
	messagesOpaque bool
	messagesDirty  bool
}

func decodeBody(raw []byte) (*requestBody, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("empty request body")
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("decode request body: %w", err)
	}
	rb := &requestBody{fields: fields}
	if rawSystem, ok := fields["system"]; ok {
		var s string
		if err := json.Unmarshal(rawSystem, &s); err == nil {
			rb.system = s
			rb.hasSystem = true
		}
	}
	if rawMessages, ok := fields["messages"]; ok {
		var msgs []json.RawMessage
		if err := json.Unmarshal(rawMessages, &msgs); err == nil {
			rb.messages = msgs
			rb.hasMessages = true
		} else {
			rb.messagesOpaque = true
		}
	}
	return rb, nil
}

func (rb *requestBody) injectSystem(mode onExistingSystem, role, content string) {
	if role != roleSystem {
		if rb.messagesOpaque {
			return
		}
		rb.prependMessage(role, content)
		return
	}
	if rb.hasSystem {
		rb.system = mergeSystem(mode, rb.system, content)
		rb.systemDirty = true
		return
	}
	if rb.messagesOpaque {
		return
	}
	if idx := rb.firstSystemIndex(); idx >= 0 {
		rb.mergeSystemMessage(idx, mode, content)
		return
	}
	rb.prependMessage(roleSystem, content)
}

func (rb *requestBody) prependMessage(role, content string) {
	entry, err := json.Marshal(message{Role: role, Content: content})
	if err != nil {
		return
	}
	rb.messages = append([]json.RawMessage{entry}, rb.messages...)
	rb.hasMessages = true
	rb.messagesDirty = true
}

func (rb *requestBody) mergeSystemMessage(idx int, mode onExistingSystem, content string) {
	entry := map[string]json.RawMessage{}
	if err := json.Unmarshal(rb.messages[idx], &entry); err != nil {
		return
	}
	existing := ""
	hasStringContent := false
	if rawContent, ok := entry["content"]; ok {
		if err := json.Unmarshal(rawContent, &existing); err == nil {
			hasStringContent = true
		}
	}
	if !hasStringContent && mode == onExistingMerge {
		rb.prependMessage(roleSystem, content)
		return
	}
	newContent := content
	if hasStringContent {
		newContent = mergeSystem(mode, existing, content)
	}
	encoded, err := json.Marshal(newContent)
	if err != nil {
		return
	}
	entry["content"] = encoded
	reEncoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rb.messages[idx] = reEncoded
	rb.messagesDirty = true
}

func (rb *requestBody) firstSystemIndex() int {
	for i := range rb.messages {
		var peek struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(rb.messages[i], &peek); err != nil {
			continue
		}
		if peek.Role == roleSystem {
			return i
		}
	}
	return -1
}

func (rb *requestBody) marshal() ([]byte, error) {
	if rb.fields == nil {
		rb.fields = map[string]json.RawMessage{}
	}
	if rb.systemDirty {
		encoded, err := json.Marshal(rb.system)
		if err != nil {
			return nil, fmt.Errorf("encode system: %w", err)
		}
		rb.fields["system"] = encoded
	}
	if rb.messagesDirty {
		encoded, err := json.Marshal(rb.messages)
		if err != nil {
			return nil, fmt.Errorf("encode messages: %w", err)
		}
		rb.fields["messages"] = encoded
	}
	out, err := json.Marshal(rb.fields)
	if err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}
	return out, nil
}

func mergeSystem(mode onExistingSystem, existing, content string) string {
	switch mode {
	case onExistingReplace:
		return content
	case onExistingMerge:
		if existing == "" {
			return content
		}
		return existing + "\n\n" + content
	default:
		if existing == "" {
			return content
		}
		return existing + "\n\n" + content
	}
}
