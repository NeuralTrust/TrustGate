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

package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ValidateAnthropicStreamEvent validates known event shapes without rejecting future event types.
func ValidateAnthropicStreamEvent(body []byte) error {
	invalid := errors.New("invalid upstream Anthropic stream event")
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(body, &kind) != nil || kind.Type == "" {
		return invalid
	}
	switch kind.Type {
	case "message_start", "message_delta", "content_block_start", "content_block_delta", "content_block_stop", "message_stop", "ping", "error":
	default:
		return nil
	}
	var event anthropicStreamEvent
	if json.Unmarshal(body, &event) != nil {
		return invalid
	}
	var raw json.RawMessage
	var target any
	switch event.Type {
	case "message_start":
		raw, target = event.Message, &anthropicMessageStart{}
	case "message_delta", "content_block_delta":
		raw, target = event.Delta, &anthropicDelta{}
	case "content_block_start":
		raw, target = event.ContentBlock, &anthropicContentBlock{}
	default:
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, target) != nil {
		return invalid
	}
	if event.Type == "content_block_delta" && target.(*anthropicDelta).Type == "" {
		return invalid
	}
	if event.Type == "content_block_start" && target.(*anthropicContentBlock).Type == "" {
		return invalid
	}
	return nil
}
