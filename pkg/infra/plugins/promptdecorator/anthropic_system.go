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
	"strings"
)

type anthropicSystem struct {
	raw          json.RawMessage
	textSegments []string
	blocks       []anthropicSystemBlock
	state        anthropicSystemState
	kind         anthropicSystemKind
	present      bool
	loaded       bool
	validated    bool
	dirty        bool
	loadErr      error
}

type anthropicSystemBlock struct {
	raw       json.RawMessage
	text      string
	generated bool
}

type anthropicSystemState uint8

const (
	anthropicSystemAbsent anthropicSystemState = iota
	anthropicSystemNonblank
	anthropicSystemOpaque
)

type anthropicSystemKind uint8

const (
	anthropicSystemKindOpaque anthropicSystemKind = iota
	anthropicSystemKindString
	anthropicSystemKindBlocks
)

func newAnthropicSystem(raw json.RawMessage, present bool) anthropicSystem {
	return anthropicSystem{raw: raw, present: present}
}

func (s *anthropicSystem) apply(content string, strategy systemStrategy) error {
	s.load()
	if s.loadErr != nil {
		return s.loadErr
	}
	if s.state == anthropicSystemAbsent {
		s.setString(content)
		return nil
	}

	switch strategy {
	case systemStrategySkip:
		return nil
	case systemStrategyMerge:
		return s.merge(content)
	case systemStrategyReplace:
		s.replace(content)
		return nil
	case systemStrategyAppend:
		return s.append(content)
	default:
		return fmt.Errorf("unsupported existing-system strategy %q", strategy)
	}
}

func (s *anthropicSystem) merge(content string) error {
	switch s.kind {
	case anthropicSystemKindString:
		s.textSegments = append(s.textSegments, content)
	case anthropicSystemKindBlocks:
		if s.state == anthropicSystemNonblank {
			content = "\n\n" + content
		}
		s.blocks = append(s.blocks, anthropicSystemBlock{text: content, generated: true})
	case anthropicSystemKindOpaque:
		return fmt.Errorf("anthropic system must be a string or array")
	}
	s.markChanged()
	return nil
}

func (s *anthropicSystem) replace(content string) {
	if s.kind == anthropicSystemKindBlocks {
		s.blocks = []anthropicSystemBlock{{text: content, generated: true}}
		s.markChanged()
		return
	}
	if s.kind == anthropicSystemKindString && strings.Join(s.textSegments, "\n\n") == content {
		return
	}
	s.setString(content)
}

func (s *anthropicSystem) append(content string) error {
	switch s.kind {
	case anthropicSystemKindString:
		s.blocks = []anthropicSystemBlock{
			{text: strings.Join(s.textSegments, "\n\n"), generated: true},
			{text: content, generated: true},
		}
		s.textSegments = nil
		s.kind = anthropicSystemKindBlocks
	case anthropicSystemKindBlocks:
		s.blocks = append(s.blocks, anthropicSystemBlock{text: content, generated: true})
	case anthropicSystemKindOpaque:
		return fmt.Errorf("anthropic system must be a string or array")
	}
	s.markChanged()
	return nil
}

func (s *anthropicSystem) setString(content string) {
	s.textSegments = []string{content}
	s.blocks = nil
	s.kind = anthropicSystemKindString
	s.markChanged()
}

func (s *anthropicSystem) markChanged() {
	s.present = true
	s.loaded = true
	s.validated = true
	s.dirty = true
	s.state = anthropicSystemNonblank
}

func (s *anthropicSystem) validate() error {
	if s.validated {
		return s.loadErr
	}
	s.load()
	s.validated = true
	s.loaded = false
	return s.loadErr
}

func (s *anthropicSystem) load() anthropicSystemState {
	if s.loaded {
		return s.state
	}
	if s.validated {
		s.loaded = true
		return s.state
	}
	s.loaded = true
	if !s.present || len(s.raw) == 0 || bytes.Equal(bytes.TrimSpace(s.raw), []byte("null")) {
		s.state = anthropicSystemAbsent
		return s.state
	}

	var text string
	if err := json.Unmarshal(s.raw, &text); err == nil {
		s.kind = anthropicSystemKindString
		s.textSegments = []string{text}
		if strings.TrimSpace(text) == "" {
			s.state = anthropicSystemAbsent
		} else {
			s.state = anthropicSystemNonblank
		}
		return s.state
	}

	if !isJSONArray(s.raw) {
		s.state = anthropicSystemOpaque
		return s.state
	}
	var rawBlocks []json.RawMessage
	if err := json.Unmarshal(s.raw, &rawBlocks); err != nil {
		s.state = anthropicSystemOpaque
		return s.state
	}
	s.kind = anthropicSystemKindBlocks
	s.blocks = make([]anthropicSystemBlock, len(rawBlocks))
	for i := range rawBlocks {
		s.blocks[i] = anthropicSystemBlock{raw: rawBlocks[i]}
	}
	s.state, s.loadErr = anthropicBlocksContentState(rawBlocks)
	if s.loadErr != nil {
		s.state = anthropicSystemOpaque
	}
	return s.state
}

func (s *anthropicSystem) marshal() (json.RawMessage, bool, error) {
	if !s.present {
		return nil, false, nil
	}
	if !s.dirty {
		return s.raw, true, nil
	}
	switch s.kind {
	case anthropicSystemKindString:
		encoded, err := json.Marshal(strings.Join(s.textSegments, "\n\n"))
		if err != nil {
			return nil, false, fmt.Errorf("encode Anthropic system content: %w", err)
		}
		return encoded, true, nil
	case anthropicSystemKindBlocks:
		blocks := make([]json.RawMessage, len(s.blocks))
		for i := range s.blocks {
			if !s.blocks[i].generated {
				blocks[i] = s.blocks[i].raw
				continue
			}
			block, err := marshalAnthropicTextBlock(s.blocks[i].text)
			if err != nil {
				return nil, false, err
			}
			blocks[i] = block
		}
		return marshalRawArray(blocks), true, nil
	default:
		return nil, false, fmt.Errorf("encode opaque Anthropic system")
	}
}

func marshalAnthropicTextBlock(text string) (json.RawMessage, error) {
	block, err := json.Marshal(struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}{
		Type: "text",
		Text: text,
	})
	if err != nil {
		return nil, fmt.Errorf("encode Anthropic system text block: %w", err)
	}
	return block, nil
}

func anthropicSystemStateOf(raw json.RawMessage) (anthropicSystemState, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return anthropicSystemAbsent, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if strings.TrimSpace(text) == "" {
			return anthropicSystemAbsent, nil
		}
		return anthropicSystemNonblank, nil
	}
	if !isJSONArray(raw) {
		return anthropicSystemOpaque, nil
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return anthropicSystemOpaque, nil
	}
	return anthropicBlocksContentState(blocks)
}

func anthropicBlocksContentState(blocks []json.RawMessage) (anthropicSystemState, error) {
	hasText := false
	hasUnsupported := false
	for i := range blocks {
		if !isJSONObject(blocks[i]) {
			hasUnsupported = true
			continue
		}
		fields, err := decodeProtocolObject(
			blocks[i],
			"Anthropic system content block",
			"type",
			"text",
		)
		if err != nil {
			return anthropicSystemOpaque, err
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
		return anthropicSystemNonblank, nil
	}
	if hasUnsupported {
		return anthropicSystemOpaque, nil
	}
	return anthropicSystemAbsent, nil
}
