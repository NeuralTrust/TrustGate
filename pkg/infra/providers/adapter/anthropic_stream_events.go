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

import "encoding/json"

type anthropicBlockType string

const (
	anthropicBlockText    anthropicBlockType = "text"
	anthropicBlockToolUse anthropicBlockType = "tool_use"
)

type anthropicSSEBlockStart struct {
	Type         string                `json:"type"`
	Index        int                   `json:"index"`
	ContentBlock anthropicSSEBlockBody `json:"content_block"`
}

type anthropicSSEBlockBody struct {
	Type anthropicBlockType `json:"type"`
	Text *string            `json:"text,omitempty"`
	*anthropicSSEToolUse
}

type anthropicSSEToolUse struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type anthropicSSEError struct {
	Type  string                `json:"type"`
	Error anthropicSSEErrorBody `json:"error"`
}

type anthropicSSEErrorBody struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func anthropicMessageStartEvent(id, model string, usage *CanonicalUsage) [][]byte {
	data, _ := json.Marshal(anthropicSSEMessageStartPayload{
		Type: "message_start",
		Message: anthropicSSEMessageInfo{
			ID:      id,
			Type:    "message",
			Role:    "assistant",
			Content: []interface{}{},
			Model:   model,
			Usage:   anthropicSSEUsageFrom(usage),
		},
	})
	return SSEEvent("message_start", data)
}

func anthropicTextBlockStartEvent(index int) [][]byte {
	empty := ""
	return anthropicBlockStartEvent(index, anthropicSSEBlockBody{Type: anthropicBlockText, Text: &empty})
}

func anthropicToolUseBlockStartEvent(index int, id, name string) [][]byte {
	return anthropicBlockStartEvent(index, anthropicSSEBlockBody{
		Type:                anthropicBlockToolUse,
		anthropicSSEToolUse: &anthropicSSEToolUse{ID: id, Name: name, Input: json.RawMessage("{}")},
	})
}

func anthropicBlockStartEvent(index int, body anthropicSSEBlockBody) [][]byte {
	data, _ := json.Marshal(anthropicSSEBlockStart{Type: "content_block_start", Index: index, ContentBlock: body})
	return SSEEvent("content_block_start", data)
}

// anthropicContentBlockDeltaEvent carries text for a text block and partial
// JSON input for a tool_use block.
func anthropicContentBlockDeltaEvent(index int, block anthropicBlockType, text string) [][]byte {
	delta := anthropicDelta{Type: "text_delta", Text: text}
	if block == anthropicBlockToolUse {
		delta = anthropicDelta{Type: "input_json_delta", PartialJSON: text}
	}
	data, _ := json.Marshal(anthropicSSEContentBlockDelta{Type: "content_block_delta", Index: index, Delta: delta})
	return SSEEvent("content_block_delta", data)
}

func anthropicContentBlockStopEvent(index int) [][]byte {
	data, _ := json.Marshal(anthropicSSEContentBlockStop{Type: "content_block_stop", Index: index})
	return SSEEvent("content_block_stop", data)
}

func anthropicMessageEndEvents(finishReason string, usage *CanonicalUsage) [][]byte {
	data, _ := json.Marshal(anthropicSSEMessageDelta{
		Type:  "message_delta",
		Delta: anthropicSSEMessageDeltaBody{StopReason: anthropicStopReason(finishReason)},
		Usage: anthropicSSEUsageFrom(usage),
	})
	lines := SSEEvent("message_delta", data)
	data, _ = json.Marshal(anthropicSSESimple{Type: "message_stop"})
	return append(lines, SSEEvent("message_stop", data)...)
}

func anthropicErrorEvent(message string) [][]byte {
	data, _ := json.Marshal(anthropicSSEError{
		Type:  "error",
		Error: anthropicSSEErrorBody{Type: "api_error", Message: message},
	})
	return SSEEvent("error", data)
}

// AnthropicStopReasonUnmapped reports whether finishReason has no Anthropic
// stop_reason and so reaches an Anthropic client as a plain end_turn, as
// Gemini's OTHER and LANGUAGE do.
func AnthropicStopReasonUnmapped(finishReason string) bool {
	switch finishReason {
	case "", "stop", "end_turn":
		return false
	default:
		return anthropicStopReason(finishReason) == "end_turn"
	}
}

// anthropicStopReason maps a canonical finish reason to an Anthropic
// stop_reason. Gemini block reasons reach the canonical model verbatim.
func anthropicStopReason(finishReason string) string {
	switch finishReason {
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "stop_sequence":
		return "stop_sequence"
	case "model_context_window_exceeded":
		return "model_context_window_exceeded"
	default:
		if refusalFinish(finishReason) {
			return "refusal"
		}
		return "end_turn"
	}
}

func refusalFinish(reason string) bool {
	switch reason {
	case "content_filter", "refusal", "SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "IMAGE_SAFETY":
		return true
	default:
		return false
	}
}
