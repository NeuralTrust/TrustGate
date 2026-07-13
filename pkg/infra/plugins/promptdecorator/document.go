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
	"io"
	"sort"
	"strings"
)

type openAIDocument struct {
	fields   map[string]json.RawMessage
	messages []json.RawMessage
	metadata []openAIMessageMetadata
	dirty    bool
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
	fields, err := decodeProtocolObject(body, "OpenAI request", "messages")
	if err != nil {
		return nil, err
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
		document.metadata[i], err = decodeOpenAIMessageMetadata(document.messages[i])
		if err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode OpenAI messages[%d]: %w", i, err)
		}
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

func transformOpenAIBody(body []byte, decorators []decorator, marshalOutput bool) ([]byte, bool, error) {
	document, err := decodeOpenAIDocument(body)
	if err != nil {
		return nil, false, err
	}
	if err := document.apply(decorators); err != nil {
		return nil, false, err
	}
	if !document.dirty || !marshalOutput {
		return nil, document.dirty, nil
	}
	output, err := document.marshal()
	if err != nil {
		return nil, false, err
	}
	return output, true, nil
}

func hasOpenAIOriginalSystem(body []byte) (bool, error) {
	messages, err := decodeOpenAIMessageArray(body)
	if err != nil {
		return false, err
	}
	for i := range messages {
		metadata, err := decodeOpenAIMessageMetadata(messages[i])
		if err != nil {
			return false, fmt.Errorf("prompt_decorator: decode OpenAI messages[%d]: %w", i, err)
		}
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
		updated, changed, err := rewriteOpenAISystemMessage(
			d.messages[index],
			item.Content,
			*item.OnExistingSystem,
		)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		d.messages[index] = updated
		d.metadata[index] = newOpenAIMessageMetadata(roleSystem)
		d.dirty = true
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
	d.dirty = true
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

func rewriteOpenAISystemMessage(
	raw json.RawMessage,
	content string,
	strategy systemStrategy,
) (json.RawMessage, bool, error) {
	fields, err := decodeProtocolObject(raw, "OpenAI system message", "role", "content")
	if err != nil {
		return nil, false, err
	}

	rawContent, exists := fields["content"]
	if !exists || bytes.Equal(bytes.TrimSpace(rawContent), []byte("null")) {
		encoded, err := json.Marshal(content)
		if err != nil {
			return nil, false, fmt.Errorf("encode OpenAI system content: %w", err)
		}
		fields["content"] = encoded
		updated, err := marshalOpenAIMessage(fields)
		return updated, true, err
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
			return nil, false, fmt.Errorf("encode OpenAI system content: %w", err)
		}
		if bytes.Equal(bytes.TrimSpace(rawContent), encoded) {
			return raw, false, nil
		}
		fields["content"] = encoded
		updated, err := marshalOpenAIMessage(fields)
		return updated, true, err
	}

	if isJSONArray(rawContent) {
		var blocks []json.RawMessage
		if err := json.Unmarshal(rawContent, &blocks); err != nil {
			return nil, false, fmt.Errorf("decode OpenAI system content blocks: %w", err)
		}
		if strategy == systemStrategyReplace {
			blocks = nil
		}
		prefix := ""
		if strategy == systemStrategyMerge {
			hasText, err := openAIBlocksHaveText(blocks)
			if err != nil {
				return nil, false, err
			}
			if hasText {
				prefix = "\n\n"
			}
		}
		block, err := json.Marshal(struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{Type: "text", Text: prefix + content})
		if err != nil {
			return nil, false, fmt.Errorf("encode OpenAI system content block: %w", err)
		}
		blocks = append(blocks, block)
		encoded, err := json.Marshal(blocks)
		if err != nil {
			return nil, false, fmt.Errorf("encode OpenAI system content blocks: %w", err)
		}
		if bytes.Equal(bytes.TrimSpace(rawContent), encoded) {
			return raw, false, nil
		}
		fields["content"] = encoded
		updated, err := marshalOpenAIMessage(fields)
		return updated, true, err
	}

	if strategy == systemStrategyReplace {
		encoded, err := json.Marshal(content)
		if err != nil {
			return nil, false, fmt.Errorf("encode OpenAI system content: %w", err)
		}
		fields["content"] = encoded
		updated, err := marshalOpenAIMessage(fields)
		return updated, true, err
	}
	return nil, false, fmt.Errorf("OpenAI system content must be a string or array")
}

func marshalOpenAIMessage(fields map[string]json.RawMessage) (json.RawMessage, error) {
	encoded, err := marshalRawObject(fields)
	if err != nil {
		return nil, fmt.Errorf("encode OpenAI system message: %w", err)
	}
	return encoded, nil
}

func decodeOpenAIMessageMetadata(raw json.RawMessage) (openAIMessageMetadata, error) {
	fields, err := decodeProtocolMessage(raw, "OpenAI message")
	if err != nil {
		return openAIMessageMetadata{}, err
	}
	var messageRole role
	if rawRole, exists := fields["role"]; exists {
		if err := json.Unmarshal(rawRole, &messageRole); err != nil {
			return openAIMessageMetadata{}, nil
		}
	}
	metadata := openAIMessageMetadata{role: messageRole}
	if messageRole != roleSystem {
		return metadata, nil
	}
	metadata.systemContentState, err = openAISystemContentStateOf(fields["content"])
	if err != nil {
		return openAIMessageMetadata{}, err
	}
	return metadata, nil
}

func newOpenAIMessageMetadata(messageRole role) openAIMessageMetadata {
	metadata := openAIMessageMetadata{role: messageRole}
	if messageRole == roleSystem {
		metadata.systemContentState = openAISystemContentNonblank
	}
	return metadata
}

func openAISystemContentStateOf(raw json.RawMessage) (openAISystemContentState, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return openAISystemContentAbsent, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if strings.TrimSpace(text) == "" {
			return openAISystemContentAbsent, nil
		}
		return openAISystemContentNonblank, nil
	}
	if !isJSONArray(raw) {
		return openAISystemContentOpaque, nil
	}

	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return openAISystemContentOpaque, nil
	}
	return openAIBlocksContentState(blocks)
}

func openAIBlocksContentState(blocks []json.RawMessage) (openAISystemContentState, error) {
	hasText := false
	hasUnsupported := false
	for i := range blocks {
		if !isJSONObject(blocks[i]) {
			hasUnsupported = true
			continue
		}
		fields, err := decodeProtocolObject(
			blocks[i],
			"OpenAI system content block",
			"type",
			"text",
		)
		if err != nil {
			return openAISystemContentOpaque, err
		}
		rawType, typeExists := fields["type"]
		rawText, textExists := fields["text"]
		if !typeExists || !textExists {
			hasUnsupported = true
			continue
		}
		var blockType string
		if err := json.Unmarshal(rawType, &blockType); err != nil || blockType != "text" {
			hasUnsupported = true
			continue
		}
		var text string
		if err := json.Unmarshal(rawText, &text); err != nil {
			hasUnsupported = true
			continue
		}
		if strings.TrimSpace(text) != "" {
			hasText = true
		}
	}
	if hasText {
		return openAISystemContentNonblank, nil
	}
	if hasUnsupported {
		return openAISystemContentOpaque, nil
	}
	return openAISystemContentAbsent, nil
}

func openAIBlocksHaveText(blocks []json.RawMessage) (bool, error) {
	state, err := openAIBlocksContentState(blocks)
	return state == openAISystemContentNonblank, err
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
	fields, err := decodeProtocolObject(body, "OpenAI request", "messages")
	if err != nil {
		return nil, err
	}
	rawMessages, exists := fields["messages"]
	if !exists {
		return []json.RawMessage{}, nil
	}
	if !isJSONArray(rawMessages) {
		return nil, fmt.Errorf("prompt_decorator: OpenAI messages must be an array")
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(rawMessages, &messages); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode OpenAI messages: %w", err)
	}
	for i := range messages {
		if !isJSONObject(messages[i]) {
			return nil, fmt.Errorf("prompt_decorator: OpenAI messages[%d] must be an object", i)
		}
		if _, err := decodeOpenAIMessageMetadata(messages[i]); err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode OpenAI messages[%d]: %w", i, err)
		}
	}
	return messages, nil
}

func decodeProtocolObject(body []byte, name string, trackedKeys ...string) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("prompt_decorator: decode %s: empty body", name)
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("prompt_decorator: %s must be a JSON object", name)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
	}
	tracked := make(map[string]struct{}, len(trackedKeys))
	for _, key := range trackedKeys {
		tracked[key] = struct{}{}
	}
	seen := make(map[string]struct{})
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
		}
		key, valid := token.(string)
		if !valid {
			return nil, fmt.Errorf("prompt_decorator: decode %s: object key must be a string", name)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("prompt_decorator: decode %s: duplicate field %q", name, key)
		}
		seen[key] = struct{}{}
		if _, exact := tracked[key]; !exact {
			for canonical := range tracked {
				if !strings.EqualFold(key, canonical) {
					continue
				}
				return nil, fmt.Errorf(
					"prompt_decorator: decode %s: invalid field alias %q",
					name,
					key,
				)
			}
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
		}
		if err := validateProtocolJSONValue(value, name); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
		}
		return nil, fmt.Errorf("prompt_decorator: decode %s: trailing JSON value", name)
	}
	return fields, nil
}

func decodeProtocolMessage(raw json.RawMessage, name string) (map[string]json.RawMessage, error) {
	fields, err := decodeProtocolObject(raw, name, "role", "content")
	if err != nil {
		return nil, err
	}
	if err := validateProtocolContentBlocks(fields["content"], name+" content"); err != nil {
		return nil, err
	}
	return fields, nil
}

func validateProtocolContentBlocks(raw json.RawMessage, name string) error {
	if !isJSONArray(raw) {
		return nil
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
	}
	for i := range blocks {
		if !isJSONObject(blocks[i]) {
			continue
		}
		if _, err := decodeProtocolObject(
			blocks[i],
			fmt.Sprintf("%s block %d", name, i),
			"type",
			"text",
		); err != nil {
			return err
		}
	}
	return nil
}

func validateProtocolJSONValue(raw json.RawMessage, name string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("prompt_decorator: decode %s: empty JSON value", name)
	}
	switch trimmed[0] {
	case '{':
		_, err := decodeProtocolObject(trimmed, name)
		return err
	case '[':
		var values []json.RawMessage
		if err := json.Unmarshal(trimmed, &values); err != nil {
			return fmt.Errorf("prompt_decorator: decode %s: %w", name, err)
		}
		for i := range values {
			if err := validateProtocolJSONValue(values[i], name); err != nil {
				return err
			}
		}
	}
	return nil
}

func isJSONArray(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}
