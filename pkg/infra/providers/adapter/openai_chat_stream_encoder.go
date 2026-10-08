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
	"crypto/rand"
	"encoding/json"
)

// OpenAIChatStreamEncoder encodes one canonical stream as Chat Completions SSE.
// It is not safe for concurrent use.
type OpenAIChatStreamEncoder struct {
	includeUsage bool
	id           string
	model        string
	started      bool
	done         bool
	aborted      bool
}

// NewOpenAIChatStreamEncoder returns an encoder with optional terminal usage.
func NewOpenAIChatStreamEncoder(includeUsage bool) *OpenAIChatStreamEncoder {
	return &OpenAIChatStreamEncoder{includeUsage: includeUsage}
}

// Content encodes role, text, reasoning and tool deltas without finish or usage.
func (e *OpenAIChatStreamEncoder) Content(chunk *CanonicalStreamChunk) [][]byte {
	if e.done || chunk == nil {
		return nil
	}
	if chunk.UpstreamError != nil {
		return e.Abort("upstream reported a stream error")
	}
	e.remember(chunk)
	if chunk.Role == "" && chunk.Delta == "" && chunk.ReasoningDelta == "" && len(chunk.ToolCallDeltas) == 0 {
		return nil
	}
	content := *chunk
	content.FinishReason, content.Usage = "", nil
	return e.encode(&content)
}

// Finish emits one finish chunk, optional merged usage, and one final DONE marker.
func (e *OpenAIChatStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done || chunk == nil {
		return nil
	}
	if chunk.UpstreamError != nil {
		return e.Abort("upstream reported a stream error")
	}
	if message, failed := FinishFailure(chunk.FinishReason); failed {
		return e.Abort(message)
	}
	if chunk.FinishReason == "" {
		return e.Abort("upstream stream ended without a finish reason")
	}
	e.remember(chunk)
	lines := e.encode(&CanonicalStreamChunk{FinishReason: chunk.FinishReason})
	if e.aborted {
		return lines
	}
	if e.includeUsage && chunk.Usage != nil {
		lines = append(lines, e.encode(&CanonicalStreamChunk{Usage: chunk.Usage})...)
		if e.aborted {
			return lines
		}
	}
	e.done = true
	return append(lines, SSEData([]byte("[DONE]"))...)
}

// Abort emits one error frame and suppresses subsequent success markers.
func (e *OpenAIChatStreamEncoder) Abort(message string) [][]byte {
	if e.done {
		return nil
	}
	e.done, e.aborted = true, true
	if message == "" {
		message = "upstream stream failed"
	}
	data, err := json.Marshal(map[string]any{"error": map[string]string{
		"type": "upstream_error", "code": "upstream_error", "message": message,
	}})
	if err != nil {
		data = []byte(`{"error":{"type":"upstream_error","code":"upstream_error","message":"upstream stream failed"}}`)
	}
	return SSEData(data)
}

// Aborted reports whether the encoder ended with an error frame.
func (e *OpenAIChatStreamEncoder) Aborted() bool {
	return e.aborted
}

func (e *OpenAIChatStreamEncoder) remember(chunk *CanonicalStreamChunk) {
	if !e.started {
		if chunk.ID != "" {
			e.id = chunk.ID
		}
		if chunk.Model != "" {
			e.model = chunk.Model
		}
	}
}

func (e *OpenAIChatStreamEncoder) encode(chunk *CanonicalStreamChunk) [][]byte {
	if e.id == "" {
		e.id = "chatcmpl-" + rand.Text()
	}
	chunk.ID, chunk.Model = e.id, e.model
	lines, err := encodeChatStreamChunk(chunk, true)
	if err != nil {
		return e.Abort("upstream stream could not be encoded")
	}
	e.started = true
	return lines
}
