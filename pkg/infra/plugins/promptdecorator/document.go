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

package promptdecorator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type openAIDocument struct {
	fields   map[string]json.RawMessage
	messages []json.RawMessage
	metadata []openAIMessageMetadata
}

type openAIMessageMetadata struct {
	role               role
	systemContentState openAISystemContentState
}

type openAISystemContentState uint8

const (
	openAISystemContentAbsent openAISystemContentState = iota
	openAISystemContentNonblank
	openAISystemContentOpaque
)

func decodeOpenAIDocument(body []byte) (*openAIDocument, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI request: empty body")
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("prompt_decorator: OpenAI request must be a JSON object")
	}

	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI request: %w", err)
	}

	document := &openAIDocument{fields: fields}
	rawMessages, exists := fields["messages"]
	if !exists {
		document.messages = []json.RawMessage{}
		return document, nil
	}
	if !isJSONArray(rawMessages) {
		return nil, fmt.Errorf("prompt_decorator: OpenAI messages must be an array")
	}
	if err := json.Unmarshal(rawMessages, &document.messages); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI messages: %w", err)
	}
	document.metadata = make([]openAIMessageMetadata, len(document.messages))
	for i := range document.messages {
		if !isJSONObject(document.messages[i]) {
			return nil, fmt.Errorf("prompt_decorator: OpenAI messages[%d] must be an object", i)
		}
		document.metadata[i] = decodeOpenAIMessageMetadata(document.messages[i])
	}
	delete(document.fields, "messages")
	return document, nil
}

func decorateOpenAIBody(body []byte, decorators []decorator) ([]byte, error) {
	document, err := decodeOpenAIDocument(body)
	if err != nil {
		return nil, err
	}
	if err := document.apply(decorators); err != nil {
		return nil, err
	}
	return document.marshal()
}

func hasOpenAIOriginalSystem(body []byte) (bool, error) {
	messages, err := decodeOpenAIMessageArray(body)
	if err != nil {
		return false, err
	}
	for i := range messages {
		metadata := decodeOpenAIMessageMetadata(messages[i])
		if metadata.role == roleSystem && metadata.systemContentState == openAISystemContentNonblank {
			return true, nil
		}
	}
	return false, nil
}

func (d *openAIDocument) apply(decorators []decorator) error {
	d.reserveInsertions(decorators)
	for i := range decorators {
		if err := d.applyDecorator(decorators[i]); err != nil {
			return fmt.Errorf("prompt_decorator: apply decorators[%d]: %w", i, err)
		}
	}
	return nil
}

func (d *openAIDocument) applyDecorator(item decorator) error {
	if item.Position == positionSystem {
		return d.applySystemDecorator(item)
	}

	message, err := newOpenAIMessage(item.Role, item.Content)
	if err != nil {
		return err
	}

	index := len(d.messages)
	switch item.Position {
	case positionStart:
		index = 0
	case positionAfterSystem:
		index = d.leadingSystemEnd()
	case positionBeforeLastUser:
		index = d.beforeLastRole(roleUser)
	case positionEnd:
	}
	d.insert(index, message, newOpenAIMessageMetadata(item.Role))
	return nil
}

func (d *openAIDocument) applySystemDecorator(item decorator) error {
	index := d.firstSystemTarget()
	if index < 0 {
		message, err := newOpenAIMessage(roleSystem, item.Content)
		if err != nil {
			return err
		}
		d.insert(d.leadingSystemEnd(), message, newOpenAIMessageMetadata(roleSystem))
		return nil
	}

	switch *item.OnExistingSystem {
	case systemStrategySkip:
		return nil
	case systemStrategyAppend:
		message, err := newOpenAIMessage(roleSystem, item.Content)
		if err != nil {
			return err
		}
		d.insert(index+1, message, newOpenAIMessageMetadata(roleSystem))
		return nil
	case systemStrategyMerge, systemStrategyReplace:
		updated, err := rewriteOpenAISystemMessage(d.messages[index], item.Content, *item.OnExistingSystem)
		if err != nil {
			return err
		}
		d.messages[index] = updated
		d.metadata[index] = newOpenAIMessageMetadata(roleSystem)
		return nil
	default:
		return fmt.Errorf("unsupported existing-system strategy %q", *item.OnExistingSystem)
	}
}

func (d *openAIDocument) insert(index int, message json.RawMessage, metadata openAIMessageMetadata) {
	d.messages = append(d.messages, nil)
	copy(d.messages[index+1:], d.messages[index:])
	d.messages[index] = message
	d.metadata = append(d.metadata, openAIMessageMetadata{})
	copy(d.metadata[index+1:], d.metadata[index:])
	d.metadata[index] = metadata
}

func (d *openAIDocument) reserveInsertions(decorators []decorator) {
	additions := 0
	systemKnown := false
	hasSystemTarget := false
	for i := range decorators {
		if decorators[i].Position != positionSystem {
			additions++
			continue
		}
		strategy := *decorators[i].OnExistingSystem
		if !systemKnown && strategy != systemStrategyAppend {
			hasSystemTarget = d.firstSystemTarget() >= 0
			systemKnown = true
		}
		if strategy == systemStrategyAppend {
			additions++
			hasSystemTarget = true
			systemKnown = true
			continue
		}
		if !hasSystemTarget {
			additions++
			hasSystemTarget = true
		}
	}
	if additions == 0 {
		return
	}
	if cap(d.messages)-len(d.messages) < additions {
		messages := make([]json.RawMessage, len(d.messages), len(d.messages)+additions)
		copy(messages, d.messages)
		d.messages = messages
	}
	if cap(d.metadata)-len(d.metadata) < additions {
		metadata := make([]openAIMessageMetadata, len(d.metadata), len(d.metadata)+additions)
		copy(metadata, d.metadata)
		d.metadata = metadata
	}
}

func (d *openAIDocument) leadingSystemEnd() int {
	index := 0
	for index < len(d.metadata) && d.metadata[index].role == roleSystem {
		index++
	}
	return index
}

func (d *openAIDocument) beforeLastRole(wanted role) int {
	for i := len(d.metadata) - 1; i >= 0; i-- {
		if d.metadata[i].role == wanted {
			return i
		}
	}
	return len(d.messages)
}

func (d *openAIDocument) firstSystemTarget() int {
	opaqueIndex := -1
	for i := range d.metadata {
		if d.metadata[i].role != roleSystem {
			continue
		}
		if d.metadata[i].systemContentState == openAISystemContentNonblank {
			return i
		}
		if d.metadata[i].systemContentState == openAISystemContentOpaque && opaqueIndex < 0 {
			opaqueIndex = i
		}
	}
	return opaqueIndex
}

func (d *openAIDocument) marshal() ([]byte, error) {
	d.fields["messages"] = marshalRawArray(d.messages)
	output, err := marshalRawObject(d.fields)
	if err != nil {
		return nil, fmt.Errorf("prompt_decorator: encode OpenAI request: %w", err)
	}
	return output, nil
}

func newOpenAIMessage(messageRole role, content string) (json.RawMessage, error) {
	message, err := json.Marshal(struct {
		Role    role   `json:"role"`
		Content string `json:"content"`
	}{
		Role:    messageRole,
		Content: content,
	})
	if err != nil {
		return nil, fmt.Errorf("encode OpenAI message: %w", err)
	}
	return message, nil
}

func rewriteOpenAISystemMessage(raw json.RawMessage, content string, strategy systemStrategy) (json.RawMessage, error) {
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("decode OpenAI system message: %w", err)
	}

	rawContent, exists := fields["content"]
	if !exists || bytes.Equal(bytes.TrimSpace(rawContent), []byte("null")) {
		encoded, err := json.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("encode OpenAI system content: %w", err)
		}
		fields["content"] = encoded
		return marshalOpenAIMessage(fields)
	}

	var text string
	if err := json.Unmarshal(rawContent, &text); err == nil {
		if strategy == systemStrategyMerge && strings.TrimSpace(text) != "" {
			text += "\n\n" + content
		} else {
			text = content
		}
		encoded, err := json.Marshal(text)
		if err != nil {
			return nil, fmt.Errorf("encode OpenAI system content: %w", err)
		}
		fields["content"] = encoded
		return marshalOpenAIMessage(fields)
	}

	if isJSONArray(rawContent) {
		var blocks []json.RawMessage
		if err := json.Unmarshal(rawContent, &blocks); err != nil {
			return nil, fmt.Errorf("decode OpenAI system content blocks: %w", err)
		}
		if strategy == systemStrategyReplace {
			blocks = nil
		}
		prefix := ""
		if strategy == systemStrategyMerge && openAIBlocksHaveText(blocks) {
			prefix = "\n\n"
		}
		block, err := json.Marshal(struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{Type: "text", Text: prefix + content})
		if err != nil {
			return nil, fmt.Errorf("encode OpenAI system content block: %w", err)
		}
		blocks = append(blocks, block)
		encoded, err := json.Marshal(blocks)
		if err != nil {
			return nil, fmt.Errorf("encode OpenAI system content blocks: %w", err)
		}
		fields["content"] = encoded
		return marshalOpenAIMessage(fields)
	}

	if strategy == systemStrategyReplace {
		encoded, err := json.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("encode OpenAI system content: %w", err)
		}
		fields["content"] = encoded
		return marshalOpenAIMessage(fields)
	}
	return nil, fmt.Errorf("OpenAI system content must be a string or array")
}

func marshalOpenAIMessage(fields map[string]json.RawMessage) (json.RawMessage, error) {
	encoded, err := marshalRawObject(fields)
	if err != nil {
		return nil, fmt.Errorf("encode OpenAI system message: %w", err)
	}
	return encoded, nil
}

func decodeOpenAIMessageMetadata(raw json.RawMessage) openAIMessageMetadata {
	var message struct {
		Role    role            `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &message); err != nil {
		return openAIMessageMetadata{}
	}
	metadata := openAIMessageMetadata{role: message.Role}
	if message.Role != roleSystem {
		return metadata
	}
	metadata.systemContentState = openAISystemContentStateOf(message.Content)
	return metadata
}

func newOpenAIMessageMetadata(messageRole role) openAIMessageMetadata {
	metadata := openAIMessageMetadata{role: messageRole}
	if messageRole == roleSystem {
		metadata.systemContentState = openAISystemContentNonblank
	}
	return metadata
}

func openAISystemContentStateOf(raw json.RawMessage) openAISystemContentState {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return openAISystemContentAbsent
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if strings.TrimSpace(text) == "" {
			return openAISystemContentAbsent
		}
		return openAISystemContentNonblank
	}
	if !isJSONArray(raw) {
		return openAISystemContentOpaque
	}

	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return openAISystemContentOpaque
	}
	return openAIBlocksContentState(blocks)
}

func openAIBlocksContentState(blocks []json.RawMessage) openAISystemContentState {
	hasUnsupported := false
	for i := range blocks {
		var block struct {
			Type string          `json:"type"`
			Text json.RawMessage `json:"text"`
		}
		if err := json.Unmarshal(blocks[i], &block); err != nil || block.Type != "text" {
			hasUnsupported = true
			continue
		}
		var text string
		if err := json.Unmarshal(block.Text, &text); err != nil {
			hasUnsupported = true
			continue
		}
		if strings.TrimSpace(text) != "" {
			return openAISystemContentNonblank
		}
	}
	if hasUnsupported {
		return openAISystemContentOpaque
	}
	return openAISystemContentAbsent
}

func openAIBlocksHaveText(blocks []json.RawMessage) bool {
	return openAIBlocksContentState(blocks) == openAISystemContentNonblank
}

func marshalRawArray(values []json.RawMessage) []byte {
	var output bytes.Buffer
	size := 2
	for i := range values {
		size += len(values[i])
		if i > 0 {
			size++
		}
	}
	output.Grow(size)
	output.WriteByte('[')
	for i := range values {
		if i > 0 {
			output.WriteByte(',')
		}
		output.Write(values[i])
	}
	output.WriteByte(']')
	return output.Bytes()
}

func marshalRawObject(fields map[string]json.RawMessage) ([]byte, error) {
	size := 2
	for key, value := range fields {
		size += len(key) + len(value) + 3
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var output bytes.Buffer
	output.Grow(size)
	output.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			output.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, fmt.Errorf("encode JSON field name: %w", err)
		}
		output.Write(encodedKey)
		output.WriteByte(':')
		output.Write(fields[key])
	}
	output.WriteByte('}')
	return output.Bytes(), nil
}

func decodeOpenAIMessageArray(body []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI request: empty body")
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("prompt_decorator: OpenAI request must be a JSON object")
	}

	var request struct {
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI request: %w", err)
	}
	if request.Messages == nil {
		return []json.RawMessage{}, nil
	}
	if !isJSONArray(request.Messages) {
		return nil, fmt.Errorf("prompt_decorator: OpenAI messages must be an array")
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(request.Messages, &messages); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI messages: %w", err)
	}
	for i := range messages {
		if !isJSONObject(messages[i]) {
			return nil, fmt.Errorf("prompt_decorator: OpenAI messages[%d] must be an object", i)
		}
	}
	return messages, nil
}

func isJSONArray(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}
