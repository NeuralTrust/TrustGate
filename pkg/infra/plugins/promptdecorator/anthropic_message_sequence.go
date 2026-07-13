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

type anthropicMessageSequence struct {
	head          *anthropicMessageNode
	tail          *anthropicMessageNode
	lastUser      *anthropicMessageNode
	lastUserKnown bool
	length        int
}

type anthropicMessageNode struct {
	raw       json.RawMessage
	role      role
	roleKnown bool
	previous  *anthropicMessageNode
	next      *anthropicMessageNode
}

func newAnthropicMessageSequence(messages []json.RawMessage) anthropicMessageSequence {
	var sequence anthropicMessageSequence
	for i := range messages {
		sequence.append(&anthropicMessageNode{raw: messages[i]})
	}
	return sequence
}

func newAnthropicMessageNode(messageRole role, content string) (*anthropicMessageNode, error) {
	message, err := json.Marshal(struct {
		Role    role   `json:"role"`
		Content string `json:"content"`
	}{
		Role:    messageRole,
		Content: content,
	})
	if err != nil {
		return nil, fmt.Errorf("encode Anthropic message: %w", err)
	}
	return &anthropicMessageNode{
		raw:       message,
		role:      messageRole,
		roleKnown: true,
	}, nil
}

func (s *anthropicMessageSequence) insert(position position, node *anthropicMessageNode) {
	switch position {
	case positionStart, positionAfterSystem:
		s.prepend(node)
	case positionBeforeLastUser:
		s.ensureLastUser()
		if s.lastUser == nil {
			s.append(node)
			return
		}
		s.insertBefore(s.lastUser, node)
	case positionEnd:
		s.append(node)
	}
}

func (s *anthropicMessageSequence) prepend(node *anthropicMessageNode) {
	node.previous = nil
	node.next = s.head
	if s.head == nil {
		s.tail = node
	} else {
		s.head.previous = node
	}
	s.head = node
	s.length++
	if s.lastUserKnown && s.lastUser == nil && node.roleKnown && node.role == roleUser {
		s.lastUser = node
	}
}

func (s *anthropicMessageSequence) append(node *anthropicMessageNode) {
	node.previous = s.tail
	node.next = nil
	if s.tail == nil {
		s.head = node
	} else {
		s.tail.next = node
	}
	s.tail = node
	s.length++
	if s.lastUserKnown && node.roleKnown && node.role == roleUser {
		s.lastUser = node
	}
}

func (s *anthropicMessageSequence) insertBefore(target, node *anthropicMessageNode) {
	node.previous = target.previous
	node.next = target
	if target.previous == nil {
		s.head = node
	} else {
		target.previous.next = node
	}
	target.previous = node
	s.length++
}

func (s *anthropicMessageSequence) ensureLastUser() {
	if s.lastUserKnown {
		return
	}
	for node := s.head; node != nil; node = node.next {
		if !node.roleKnown {
			node.role = decodeAnthropicMessageRole(node.raw)
			node.roleKnown = true
		}
		if node.role == roleUser {
			s.lastUser = node
		}
	}
	s.lastUserKnown = true
}

func (s *anthropicMessageSequence) rawMessages() []json.RawMessage {
	messages := make([]json.RawMessage, 0, s.length)
	for node := s.head; node != nil; node = node.next {
		messages = append(messages, node.raw)
	}
	return messages
}

func decodeAnthropicMessageRole(raw json.RawMessage) role {
	rawRole, exists := decodeExactJSONObjectField(raw, "role")
	if !exists {
		return ""
	}
	var messageRole role
	if err := json.Unmarshal(rawRole, &messageRole); err != nil {
		return ""
	}
	return messageRole
}
