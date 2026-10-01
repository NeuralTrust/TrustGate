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
	"strings"
)

const (
	reasonMessagesNotArray         = "messages_not_array"
	reasonContentsNotArray         = "contents_not_array"
	reasonEncodeFailed             = "encode_failed"
	reasonSystemMessageUnreadable  = "system_message_unreadable"
	reasonSystemInstructionBad     = "system_instruction_unreadable"
	reasonSystemUnreadable         = "system_unreadable"
	reasonRoleUnsupportedGemini    = "role_not_supported_on_gemini"
	reasonRoleUnsupportedAnthropic = "role_not_supported_on_anthropic"
)

// The Gemini shape is edited as raw fields only. Decoding it into the
// canonical request and encoding it back is lossy (inline data, thought
// signatures, unmodelled fields), so every edit below rewrites just the one
// field it owns and writes it back under the spelling the client used.

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func geminiTextPart(text string) json.RawMessage {
	part, _ := json.Marshal(map[string]string{"text": text})
	return part
}

// systemInstructionKey is the spelling of the system instruction field the
// client used; camelCase when the body has neither.
func (rb *requestBody) systemInstructionKey() string {
	if _, ok := rb.fields["systemInstruction"]; ok {
		return "systemInstruction"
	}
	if _, ok := rb.fields["system_instruction"]; ok {
		return "system_instruction"
	}
	return "systemInstruction"
}

// geminiContents returns the contents array, or nil when absent or not an array.
func (rb *requestBody) geminiContents() []json.RawMessage {
	raw, ok := rb.fields["contents"]
	if !ok {
		return nil
	}
	var contents []json.RawMessage
	if err := json.Unmarshal(raw, &contents); err != nil {
		return nil
	}
	return contents
}

func (rb *requestBody) setGeminiContents(contents []json.RawMessage) error {
	if contents == nil {
		contents = []json.RawMessage{}
	}
	encoded, err := json.Marshal(contents)
	if err != nil {
		return fmt.Errorf("encode contents: %w", err)
	}
	rb.fields["contents"] = encoded
	rb.rawDirty = true
	return nil
}

func (rb *requestBody) injectGemini(mode onExistingSystem, role, content string) (bool, string) {
	if role == roleSystem {
		return rb.injectGeminiSystem(mode, content)
	}
	// Only system and user apply: whether Gemini accepts a conversation that
	// opens with a model turn is unverified, so assistant is reported rather
	// than guessed at.
	if role != roleUser {
		return false, reasonRoleUnsupportedGemini
	}
	geminiRole := "user"
	var contents []json.RawMessage
	if raw, ok := rb.fields["contents"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &contents); err != nil {
			return false, reasonContentsNotArray
		}
	}
	turn, err := json.Marshal(map[string]any{
		"role":  geminiRole,
		"parts": []json.RawMessage{geminiTextPart(content)},
	})
	if err != nil {
		return false, reasonEncodeFailed
	}
	next := make([]json.RawMessage, 0, len(contents)+1)
	next = append(next, turn)
	next = append(next, contents...)
	if err := rb.setGeminiContents(next); err != nil {
		return false, reasonEncodeFailed
	}
	return true, ""
}

func (rb *requestBody) injectGeminiSystem(mode onExistingSystem, content string) (bool, string) {
	key := rb.systemInstructionKey()
	obj := map[string]json.RawMessage{}
	if raw, ok := rb.fields[key]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return false, reasonSystemInstructionBad
		}
	}
	var parts []json.RawMessage
	if raw, ok := obj["parts"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &parts); err != nil {
			return false, reasonSystemInstructionBad
		}
	}
	part := geminiTextPart(content)
	if mode == onExistingReplace {
		parts = []json.RawMessage{part}
	} else {
		next := make([]json.RawMessage, 0, len(parts)+1)
		next = append(next, parts...)
		parts = append(next, part)
	}
	encodedParts, err := json.Marshal(parts)
	if err != nil {
		return false, reasonEncodeFailed
	}
	obj["parts"] = encodedParts
	encoded, err := json.Marshal(obj)
	if err != nil {
		return false, reasonEncodeFailed
	}
	rb.fields[key] = encoded
	rb.rawDirty = true
	return true, ""
}

// findGeminiReferences scans the string text parts of every turn. Thought
// parts are the model's own reasoning, not caller input, so they are skipped.
func (rb *requestBody) findGeminiReferences() []templateRef {
	var refs []templateRef
	for _, rawContent := range rb.geminiContents() {
		var content struct {
			Parts []json.RawMessage `json:"parts"`
		}
		if err := json.Unmarshal(rawContent, &content); err != nil {
			continue
		}
		for _, rawPart := range content.Parts {
			var part struct {
				Text    json.RawMessage `json:"text"`
				Thought json.RawMessage `json:"thought"`
			}
			if err := json.Unmarshal(rawPart, &part); err != nil {
				continue
			}
			if bytes.Equal(bytes.TrimSpace(part.Thought), []byte("true")) {
				continue
			}
			var text string
			if err := json.Unmarshal(part.Text, &text); err != nil {
				continue
			}
			refs = append(refs, scanReferences(text)...)
		}
	}
	return refs
}

// replaceGeminiContents is replaceMessages for a Gemini body. An OpenAI-style
// messages fragment is mapped turn by turn: system folds into the system
// instruction, assistant becomes model, anything else user. A plain string is
// one user turn.
func (rb *requestBody) replaceGeminiContents(rendered string) error {
	if !strings.HasPrefix(strings.TrimSpace(rendered), "[") {
		turn, err := geminiTurn("user", []string{rendered})
		if err != nil {
			return err
		}
		return rb.setGeminiContents([]json.RawMessage{turn})
	}
	var fragment []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal([]byte(rendered), &fragment); err != nil {
		return fmt.Errorf("parse rendered messages fragment: %w", err)
	}
	turns := make([]json.RawMessage, 0, len(fragment))
	var system []string
	for _, m := range fragment {
		texts, err := fragmentTexts(m.Content)
		if err != nil {
			return err
		}
		switch m.Role {
		case roleSystem:
			if text := strings.Join(texts, "\n\n"); text != "" {
				system = append(system, text)
			}
		default:
			if len(texts) == 0 {
				continue
			}
			role := "user"
			if m.Role == "assistant" {
				role = "model"
			}
			turn, err := geminiTurn(role, texts)
			if err != nil {
				return err
			}
			turns = append(turns, turn)
		}
	}
	if err := rb.setGeminiContents(turns); err != nil {
		return err
	}
	if len(system) > 0 {
		if applied, reason := rb.injectGeminiSystem(onExistingMerge, strings.Join(system, "\n\n")); !applied {
			return fmt.Errorf("fold rendered system message into systemInstruction: %s", reason)
		}
	}
	return nil
}

func geminiTurn(role string, texts []string) (json.RawMessage, error) {
	parts := make([]json.RawMessage, 0, len(texts))
	for _, t := range texts {
		parts = append(parts, geminiTextPart(t))
	}
	turn, err := json.Marshal(map[string]any{"role": role, "parts": parts})
	if err != nil {
		return nil, fmt.Errorf("encode rendered turn: %w", err)
	}
	return turn, nil
}

// fragmentTexts reads the text of one rendered message: a string, or an array
// of {"type":"text","text":...} parts. Anything else cannot be expressed as
// Gemini text parts and is rejected rather than dropped.
func fragmentTexts(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || isJSONNull(raw) {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []string{s}, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("rendered message content is neither a string nor text parts")
	}
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		if p.Type != "text" {
			return nil, fmt.Errorf("rendered message content part %q has no Gemini equivalent", p.Type)
		}
		texts = append(texts, p.Text)
	}
	return texts, nil
}
