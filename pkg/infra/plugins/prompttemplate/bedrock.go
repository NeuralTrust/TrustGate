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
	"encoding/json"
	"fmt"
	"strings"
)

const (
	reasonRoleUnsupportedBedrock = "role_not_supported_on_bedrock"
	reasonBedrockSystemBad       = "bedrock_system_unreadable"
	reasonBedrockMessageBad      = "bedrock_message_unreadable"
	reasonEmptyContent           = "empty_content"
)

// The Bedrock shape is Converse: system is a list of {text} blocks and messages
// a list of {role, content:[{text}...]} turns (adapter.ConverseRequest). Roles
// are user and assistant only, and a conversation must open with a user turn,
// so only system and user apply as injections.

func joinTexts(texts []string) string { return strings.Join(texts, "\n\n") }

func bedrockTextBlock(text string) json.RawMessage {
	block, _ := json.Marshal(map[string]string{"text": text})
	return block
}

func (rb *requestBody) injectBedrock(mode onExistingSystem, role, content string) (bool, string) {
	// Bedrock rejects a blank text block, and an injection of one would be
	// reported as applied while the request fails upstream.
	if strings.TrimSpace(content) == "" {
		return false, reasonEmptyContent
	}
	switch role {
	case roleSystem:
		return rb.injectBedrockSystem(mode, content)
	case roleUser:
		if rb.messagesOpaque {
			return false, reasonMessagesNotArray
		}
		return rb.injectBedrockUser(content)
	default:
		return false, reasonRoleUnsupportedBedrock
	}
}

// injectBedrockUser puts the text at the front of the conversation. Converse
// requires turns to alternate (adapter.appendConverseMessage) and a
// Bedrock-to-Bedrock request is forwarded raw, so a new user turn in front of
// a first user turn would be refused upstream: the block is prepended to that
// turn instead. A new turn is created only when there are no messages or the
// first one is the assistant's.
func (rb *requestBody) injectBedrockUser(content string) (bool, string) {
	if len(rb.messages) > 0 {
		var first map[string]json.RawMessage
		if err := json.Unmarshal(rb.messages[0], &first); err != nil || first == nil {
			return false, reasonBedrockMessageBad
		}
		// ConverseMessage matches its keys with Unicode folding, so a "Role"
		// or "Content" is the field too; editing "content" beside it would
		// leave two copies. Refuse rather than guess which one wins.
		for k := range first {
			if (k != "role" && strings.EqualFold(k, "role")) || (k != "content" && strings.EqualFold(k, "content")) {
				return false, reasonBedrockMessageBad
			}
		}
		var role string
		_ = json.Unmarshal(first["role"], &role)
		if role == "user" {
			var blocks []json.RawMessage
			if raw, ok := first["content"]; ok && !isJSONNull(raw) {
				if err := json.Unmarshal(raw, &blocks); err != nil {
					return false, reasonBedrockMessageBad
				}
			}
			next := make([]json.RawMessage, 0)
			next = append(next, bedrockTextBlock(content))
			next = append(next, blocks...)
			encodedBlocks, err := json.Marshal(next)
			if err != nil {
				return false, reasonEncodeFailed
			}
			first["content"] = encodedBlocks
			encoded, err := json.Marshal(first)
			if err != nil {
				return false, reasonEncodeFailed
			}
			msgs := make([]json.RawMessage, len(rb.messages))
			copy(msgs, rb.messages)
			msgs[0] = encoded
			rb.messages = msgs
			rb.messagesDirty = true
			return true, ""
		}
	}
	turn, err := bedrockTurn("user", []string{content})
	if err != nil {
		return false, reasonEncodeFailed
	}
	rb.messages = append([]json.RawMessage{turn}, rb.messages...)
	rb.hasMessages = true
	rb.messagesDirty = true
	return true, ""
}

func (rb *requestBody) injectBedrockSystem(mode onExistingSystem, content string) (bool, string) {
	var blocks []json.RawMessage
	if raw, ok := rb.fields["system"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return false, reasonBedrockSystemBad
		}
	}
	block := bedrockTextBlock(content)
	if mode == onExistingReplace {
		blocks = []json.RawMessage{block}
	} else {
		next := make([]json.RawMessage, 0)
		next = append(next, blocks...)
		blocks = append(next, block)
	}
	encoded, err := json.Marshal(blocks)
	if err != nil {
		return false, reasonEncodeFailed
	}
	rb.fields["system"] = encoded
	rb.rawDirty = true
	return true, ""
}

func bedrockTurn(role string, texts []string) (json.RawMessage, error) {
	blocks := make([]json.RawMessage, 0, len(texts))
	for _, t := range texts {
		blocks = append(blocks, bedrockTextBlock(t))
	}
	turn, err := json.Marshal(map[string]any{"role": role, "content": blocks})
	if err != nil {
		return nil, fmt.Errorf("encode rendered turn: %w", err)
	}
	return turn, nil
}

// findBedrockReferences scans the text blocks of every message.
func (rb *requestBody) findBedrockReferences() []templateRef {
	var refs []templateRef
	for _, rawMsg := range rb.messages {
		var msg struct {
			Content []json.RawMessage `json:"content"`
		}
		if json.Unmarshal(rawMsg, &msg) != nil {
			continue
		}
		for _, rawBlock := range msg.Content {
			var block struct {
				Text json.RawMessage `json:"text"`
			}
			if json.Unmarshal(rawBlock, &block) != nil {
				continue
			}
			var text string
			if json.Unmarshal(block.Text, &text) == nil {
				refs = append(refs, scanReferences(text)...)
			}
		}
	}
	return refs
}

// replaceBedrockMessages is replaceMessages for a Converse body. Assistant
// stays assistant and every other role becomes user; adjacent turns of the same
// role are coalesced as adapter.appendConverseMessage does, since Converse
// requires alternation. Blank text is dropped (Bedrock rejects it), and system
// text is merged into the system blocks. A plain string is one user turn.
func (rb *requestBody) replaceBedrockMessages(rendered string) error {
	frag, err := parseFragment(rendered)
	if err != nil {
		return err
	}
	var turns []bedrockTurnParts
	if frag.isPlain {
		turns = append(turns, bedrockTurnParts{role: "user", texts: []string{frag.plain}})
	} else {
		for _, t := range frag.turns {
			role := "user"
			if t.role == "assistant" {
				role = "assistant"
			}
			turns = append(turns, bedrockTurnParts{role: role, texts: t.texts})
		}
	}
	var merged []bedrockTurnParts
	for _, t := range turns {
		var texts []string
		for _, text := range t.texts {
			if strings.TrimSpace(text) != "" {
				texts = append(texts, text)
			}
		}
		if len(texts) == 0 {
			continue
		}
		if n := len(merged); n > 0 && merged[n-1].role == t.role {
			merged[n-1].texts = append(merged[n-1].texts, texts...)
			continue
		}
		merged = append(merged, bedrockTurnParts{role: t.role, texts: texts})
	}
	if len(merged) > 0 && merged[0].role != "user" {
		return &fragmentError{msg: "rendered template must open with a user turn on Bedrock, but its first turn is the assistant's"}
	}
	out := make([]json.RawMessage, 0, len(merged))
	for _, t := range merged {
		turn, err := bedrockTurn(t.role, t.texts)
		if err != nil {
			return err
		}
		out = append(out, turn)
	}
	if len(out) == 0 {
		return &fragmentError{msg: "rendered template has no conversation turns"}
	}
	rb.messages = out
	rb.hasMessages = true
	rb.messagesOpaque = false
	rb.messagesDirty = true
	if strings.TrimSpace(frag.system) != "" {
		if applied, reason := rb.injectBedrockSystem(onExistingMerge, frag.system); !applied {
			return foldError("system", reason)
		}
	}
	return nil
}

type bedrockTurnParts struct {
	role  string
	texts []string
}
