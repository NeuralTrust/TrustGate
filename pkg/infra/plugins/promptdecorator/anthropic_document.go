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
	"encoding/json"
	"fmt"
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
	system := newAnthropicSystem(rawSystem, systemPresent)

	rawMessages, messagesPresent := fields["messages"]
	delete(fields, "messages")
	if !messagesPresent {
		return &anthropicDocument{
			fields:   fields,
			system:   system,
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
		if _, err := decodeProtocolObject(messages[i], "Anthropic message", "role"); err != nil {
			return nil, fmt.Errorf("prompt_decorator: decode Anthropic messages[%d]: %w", i, err)
		}
	}
	return &anthropicDocument{
		fields:   fields,
		system:   system,
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

func transformAnthropicBody(body []byte, decorators []decorator, marshalOutput bool) ([]byte, bool, error) {
	document, err := decodeAnthropicDocument(body)
	if err != nil {
		return nil, false, err
	}
	if err := document.apply(decorators); err != nil {
		return nil, false, err
	}
	changed := document.system.dirty || document.messages.dirty
	if !changed || !marshalOutput {
		return nil, changed, nil
	}
	output, err := document.marshal()
	if err != nil {
		return nil, false, err
	}
	return output, true, nil
}

func hasAnthropicOriginalSystem(body []byte) (bool, error) {
	rawSystem, err := decodeExactAnthropicSystem(body)
	if err != nil {
		return false, err
	}
	state, err := anthropicSystemStateOf(rawSystem)
	if err != nil {
		return false, err
	}
	return state == anthropicSystemNonblank, nil
}

func decodeAnthropicFields(body []byte) (map[string]json.RawMessage, error) {
	return decodeProtocolObject(body, "Anthropic request", "system", "messages")
}

func decodeExactAnthropicSystem(body []byte) (json.RawMessage, error) {
	fields, err := decodeProtocolObject(body, "Anthropic request", "system")
	if err != nil {
		return nil, err
	}
	return fields["system"], nil
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
	if err := d.system.validate(); err != nil {
		return fmt.Errorf("prompt_decorator: decode Anthropic system: %w", err)
	}
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
