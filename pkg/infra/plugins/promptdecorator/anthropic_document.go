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
)

type anthropicDocument struct {
	fields   map[string]json.RawMessage
	system   anthropicSystem
	messages anthropicMessageSequence
}

func decodeAnthropicDocument(body []byte) (*anthropicDocument, error) {
	fields, err := decodeAnthropicFields(body)
	if err != nil {
		return nil, err
	}

	rawSystem, systemPresent := fields["system"]
	delete(fields, "system")

	rawMessages, messagesPresent := fields["messages"]
	delete(fields, "messages")
	if !messagesPresent {
		return &anthropicDocument{
			fields:   fields,
			system:   newAnthropicSystem(rawSystem, systemPresent),
			messages: newAnthropicMessageSequence(nil),
		}, nil
	}
	if !isJSONArray(rawMessages) {
		return nil, fmt.Errorf("prompt_decorator: Anthropic messages must be an array")
	}

	var messages []json.RawMessage
	if err := json.Unmarshal(rawMessages, &messages); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode Anthropic messages: %w", err)
	}
	for i := range messages {
		if !isJSONObject(messages[i]) {
			return nil, fmt.Errorf("prompt_decorator: Anthropic messages[%d] must be an object", i)
		}
	}
	return &anthropicDocument{
		fields:   fields,
		system:   newAnthropicSystem(rawSystem, systemPresent),
		messages: newAnthropicMessageSequence(messages),
	}, nil
}

func decorateAnthropicBody(body []byte, decorators []decorator) ([]byte, error) {
	document, err := decodeAnthropicDocument(body)
	if err != nil {
		return nil, err
	}
	if err := document.apply(decorators); err != nil {
		return nil, err
	}
	return document.marshal()
}

func hasAnthropicOriginalSystem(body []byte) (bool, error) {
	rawSystem, err := decodeExactAnthropicSystem(body)
	if err != nil {
		return false, err
	}
	return anthropicSystemStateOf(rawSystem) == anthropicSystemNonblank, nil
}

func decodeAnthropicFields(body []byte) (map[string]json.RawMessage, error) {
	if err := validateAnthropicObject(body); err != nil {
		return nil, err
	}
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
	}
	return fields, nil
}

func validateAnthropicObject(body []byte) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return fmt.Errorf("prompt_decorator: decode Anthropic request: empty body")
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("prompt_decorator: Anthropic request must be a JSON object")
	}
	return nil
}

func decodeExactAnthropicSystem(body []byte) (json.RawMessage, error) {
	if err := validateAnthropicObject(body); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
	}

	var system json.RawMessage
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
		}
		key, valid := token.(string)
		if !valid {
			return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: object key must be a string")
		}
		if key == "system" {
			if err := decoder.Decode(&system); err != nil {
				return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
			}
			continue
		}
		if err := skipJSONValue(decoder); err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: %w", err)
		}
		return nil, fmt.Errorf("prompt_decorator: decode Anthropic request: trailing JSON value")
	}
	return system, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	switch delimiter {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := skipJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	_, err = decoder.Token()
	return err
}

func decodeExactJSONObjectField(raw json.RawMessage, key string) (json.RawMessage, bool) {
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false
	}
	value, exists := fields[key]
	return value, exists
}

func (d *anthropicDocument) apply(decorators []decorator) error {
	for i := range decorators {
		if err := d.applyDecorator(decorators[i]); err != nil {
			return fmt.Errorf("prompt_decorator: apply decorators[%d]: %w", i, err)
		}
	}
	return nil
}

func (d *anthropicDocument) applyDecorator(item decorator) error {
	if item.Position == positionSystem {
		return d.system.apply(item.Content, *item.OnExistingSystem)
	}
	node, err := newAnthropicMessageNode(item.Role, item.Content)
	if err != nil {
		return err
	}
	d.messages.insert(item.Position, node)
	return nil
}

func (d *anthropicDocument) loadSystemState() anthropicSystemState {
	return d.system.load()
}

func (d *anthropicDocument) marshal() ([]byte, error) {
	d.fields["messages"] = marshalRawArray(d.messages.rawMessages())
	rawSystem, systemPresent, err := d.system.marshal()
	if err != nil {
		return nil, err
	}
	if systemPresent {
		d.fields["system"] = rawSystem
	}
	defer delete(d.fields, "messages")
	defer delete(d.fields, "system")

	output, err := marshalRawObject(d.fields)
	if err != nil {
		return nil, fmt.Errorf("prompt_decorator: encode Anthropic request: %w", err)
	}
	return output, nil
}
