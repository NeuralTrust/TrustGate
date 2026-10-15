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
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	roleSystem = "system"
	roleUser   = "user"
)

var templateRefRe = regexp.MustCompile(`\{template://([\w.-]+)(?:@([\w.-]+))?\}`)

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type templateRef struct {
	name  string
	label string
}

func (r templateRef) String() string {
	if r.label == "" {
		return r.name
	}
	return r.name + "@" + r.label
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

	// shape selects the wire format the body is edited as. The zero value is
	// the OpenAI-style shape (system string plus messages array), which is also
	// what a request whose format cannot be resolved is treated as.
	shape bodyShape
	// systemBlocks holds an Anthropic system prompt sent as an array of content
	// blocks. hasSystem stays false for it: only the Anthropic shape edits it.
	systemBlocks    []json.RawMessage
	hasSystemBlocks bool
	// rawDirty marks edits written straight into fields (Anthropic blocks and
	// Gemini), where the typed system and messages mirrors are not used.
	rawDirty bool
	// format is the wire format the body was recognised as; empty when it
	// could not be resolved.
	format adapter.Format
}

type bodyShape int

const (
	shapeMessages bodyShape = iota
	shapeAnthropic
	shapeGemini
	shapeResponses
	shapeBedrock
)

func (rb *requestBody) dirty() bool {
	return rb.systemDirty || rb.messagesDirty || rb.rawDirty
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
		} else if bytes.HasPrefix(bytes.TrimSpace(rawSystem), []byte("[")) {
			var blocks []json.RawMessage
			if err := json.Unmarshal(rawSystem, &blocks); err == nil {
				rb.systemBlocks = blocks
				rb.hasSystemBlocks = true
			}
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

// injectSystem applies one injection and reports whether it reached the
// request. When it did not, the second result names why, so the caller never
// records an injection the model will not see.
func (rb *requestBody) injectSystem(mode onExistingSystem, role, content string) (bool, string) {
	switch rb.shape {
	case shapeGemini:
		return rb.injectGemini(mode, role, content)
	case shapeResponses:
		return rb.injectResponses(mode, role, content)
	case shapeBedrock:
		return rb.injectBedrock(mode, role, content)
	}
	if rb.shape == shapeAnthropic {
		return rb.injectAnthropic(mode, role, content)
	}
	if role != roleSystem {
		if rb.messagesOpaque {
			return false, reasonMessagesNotArray
		}
		return rb.prependMessage(role, content), reasonEncodeFailed
	}
	if rb.hasSystem {
		rb.system = mergeSystem(mode, rb.system, content)
		rb.systemDirty = true
		return true, ""
	}
	if rb.messagesOpaque {
		return false, reasonMessagesNotArray
	}
	if idx := rb.firstSystemIndex(); idx >= 0 {
		return rb.mergeSystemMessage(idx, mode, content), reasonSystemMessageUnreadable
	}
	return rb.prependMessage(roleSystem, content), reasonEncodeFailed
}

// injectAnthropic places one injection in an Anthropic Messages body. The
// system prompt lives in the top-level system field, never in a system-role
// turn, which the API rejects. Without a usable system (absent, null, or an
// object) the field is created as a plain string.
func (rb *requestBody) injectAnthropic(mode onExistingSystem, role, content string) (bool, string) {
	switch role {
	case roleSystem:
		if rb.hasSystemBlocks {
			return rb.injectSystemBlocks(mode, content)
		}
		if rb.hasSystem {
			rb.system = mergeSystem(mode, rb.system, content)
		} else if raw, present := rb.fields["system"]; present && !isJSONNull(raw) {
			// An object, number or bool: not a prompt this plugin can read, and
			// overwriting it would silently drop what the client sent.
			return false, reasonSystemUnreadable
		} else {
			rb.system = content
			rb.hasSystem = true
		}
		rb.systemDirty = true
		return true, ""
	case roleUser, "assistant":
		// assistant is prepended as a message, as it always was for Anthropic
		// configs; kept so existing policies do not change behaviour.
		if rb.messagesOpaque {
			return false, reasonMessagesNotArray
		}
		return rb.prependMessage(role, content), reasonEncodeFailed
	default:
		return false, reasonRoleUnsupportedAnthropic
	}
}

// injectSystemBlocks edits an Anthropic system prompt sent as content blocks.
// Merge appends a text block, so cache_control and any other field on the
// existing blocks stay untouched; replace collapses the prompt to a string.
func (rb *requestBody) injectSystemBlocks(mode onExistingSystem, content string) (bool, string) {
	var encoded json.RawMessage
	var err error
	if mode == onExistingReplace {
		encoded, err = json.Marshal(content)
		if err != nil {
			return false, reasonEncodeFailed
		}
		rb.systemBlocks = nil
		rb.hasSystemBlocks = false
		rb.hasSystem = true
		rb.system = content
	} else {
		block, err := json.Marshal(map[string]string{"type": "text", "text": content})
		if err != nil {
			return false, reasonEncodeFailed
		}
		blocks := make([]json.RawMessage, 0)
		blocks = append(blocks, rb.systemBlocks...)
		blocks = append(blocks, block)
		rb.systemBlocks = blocks
		encoded, err = json.Marshal(blocks)
		if err != nil {
			return false, reasonEncodeFailed
		}
	}
	rb.fields["system"] = encoded
	rb.rawDirty = true
	return true, ""
}

func (rb *requestBody) prependMessage(role, content string) bool {
	entry, err := json.Marshal(message{Role: role, Content: content})
	if err != nil {
		return false
	}
	rb.messages = append([]json.RawMessage{entry}, rb.messages...)
	rb.hasMessages = true
	rb.messagesDirty = true
	return true
}

func (rb *requestBody) mergeSystemMessage(idx int, mode onExistingSystem, content string) bool {
	entry := map[string]json.RawMessage{}
	if err := json.Unmarshal(rb.messages[idx], &entry); err != nil {
		return false
	}
	existing := ""
	hasStringContent := false
	if rawContent, ok := entry["content"]; ok {
		if err := json.Unmarshal(rawContent, &existing); err == nil {
			hasStringContent = true
		}
	}
	if !hasStringContent && mode == onExistingMerge {
		return rb.prependMessage(roleSystem, content)
	}
	newContent := content
	if hasStringContent {
		newContent = mergeSystem(mode, existing, content)
	}
	encoded, err := json.Marshal(newContent)
	if err != nil {
		return false
	}
	entry["content"] = encoded
	reEncoded, err := json.Marshal(entry)
	if err != nil {
		return false
	}
	rb.messages[idx] = reEncoded
	rb.messagesDirty = true
	return true
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

func (rb *requestBody) clone() *requestBody {
	fields := make(map[string]json.RawMessage, len(rb.fields))
	for k, v := range rb.fields {
		fields[k] = v
	}
	var messages []json.RawMessage
	if rb.messages != nil {
		messages = make([]json.RawMessage, len(rb.messages))
		copy(messages, rb.messages)
	}
	return &requestBody{
		fields:         fields,
		system:         rb.system,
		hasSystem:      rb.hasSystem,
		systemDirty:    rb.systemDirty,
		messages:       messages,
		hasMessages:    rb.hasMessages,
		messagesOpaque: rb.messagesOpaque,
		messagesDirty:  rb.messagesDirty,

		shape:           rb.shape,
		systemBlocks:    rb.systemBlocks,
		hasSystemBlocks: rb.hasSystemBlocks,
		rawDirty:        rb.rawDirty,
		format:          rb.format,
	}
}

func (rb *requestBody) takeProperties() (map[string]any, bool) {
	if rb.fields == nil {
		return nil, false
	}
	raw, ok := rb.fields["properties"]
	if !ok {
		return nil, false
	}
	delete(rb.fields, "properties")
	props := map[string]any{}
	if err := json.Unmarshal(raw, &props); err != nil {
		return nil, true
	}
	return props, true
}

func (rb *requestBody) findReferences() []templateRef {
	switch rb.shape {
	case shapeGemini:
		return rb.findGeminiReferences()
	case shapeResponses:
		return rb.findResponsesReferences()
	case shapeBedrock:
		return rb.findBedrockReferences()
	}
	var refs []templateRef
	for i := range rb.messages {
		var entry struct {
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(rb.messages[i], &entry); err != nil {
			continue
		}
		var content string
		if err := json.Unmarshal(entry.Content, &content); err != nil {
			continue
		}
		refs = append(refs, scanReferences(content)...)
	}
	return refs
}

func scanReferences(s string) []templateRef {
	matches := templateRefRe.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	refs := make([]templateRef, 0, len(matches))
	for _, m := range matches {
		refs = append(refs, templateRef{name: m[1], label: m[2]})
	}
	return refs
}

// turnCount is the number of conversation turns the body carries, which a
// rendered template replaces.
func (rb *requestBody) turnCount() int {
	switch rb.shape {
	case shapeGemini:
		return len(rb.geminiContents())
	case shapeResponses:
		return rb.responsesTurnCount()
	}
	return len(rb.messages)
}

func (rb *requestBody) replaceMessages(rendered string) error {
	switch rb.shape {
	case shapeGemini:
		return rb.replaceGeminiContents(rendered)
	case shapeResponses:
		return rb.replaceResponsesInput(rendered)
	case shapeBedrock:
		return rb.replaceBedrockMessages(rendered)
	case shapeAnthropic:
		return rb.replaceAnthropicMessages(rendered)
	}
	return rb.replaceMessagesDefault(rendered)
}

func (rb *requestBody) replaceMessagesDefault(rendered string) error {
	if strings.HasPrefix(strings.TrimSpace(rendered), "[") {
		var msgs []json.RawMessage
		if err := json.Unmarshal([]byte(rendered), &msgs); err != nil {
			return fmt.Errorf("parse rendered messages fragment: %w", err)
		}
		rb.messages = msgs
		rb.hasMessages = true
		rb.messagesOpaque = false
		rb.messagesDirty = true
		return nil
	}
	entry, err := json.Marshal(message{Role: roleUser, Content: rendered})
	if err != nil {
		return fmt.Errorf("encode rendered message: %w", err)
	}
	rb.messages = []json.RawMessage{entry}
	rb.hasMessages = true
	rb.messagesOpaque = false
	rb.messagesDirty = true
	return nil
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

// replaceAnthropicMessages is replaceMessages for an Anthropic body. Messages
// of the fragment are kept verbatim, except system ones: Anthropic has no
// system role, so their text is merged into the top-level system field.
func (rb *requestBody) replaceAnthropicMessages(rendered string) error {
	if !strings.HasPrefix(strings.TrimSpace(rendered), "[") {
		return rb.replaceMessagesDefault(rendered)
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal([]byte(rendered), &msgs); err != nil {
		return fmt.Errorf("parse rendered messages fragment: %w", err)
	}
	kept := make([]json.RawMessage, 0, len(msgs))
	var system []string
	for _, raw := range msgs {
		var m struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(raw, &m); err != nil || m.Role != roleSystem {
			kept = append(kept, raw)
			continue
		}
		texts, err := fragmentTexts(m.Content)
		if err != nil {
			return err
		}
		if text := strings.Join(texts, "\n\n"); text != "" {
			system = append(system, text)
		}
	}
	rb.messages = kept
	rb.hasMessages = true
	rb.messagesOpaque = false
	rb.messagesDirty = true
	if len(system) > 0 {
		if applied, reason := rb.injectAnthropic(onExistingMerge, roleSystem, strings.Join(system, "\n\n")); !applied {
			return foldError("system", reason)
		}
	}
	return nil
}
