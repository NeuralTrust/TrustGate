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

// ResponsesStreamEncoder encodes a canonical stream as Responses API events,
// giving the message and each function call its own output_index; not safe
// for concurrent use.
type ResponsesStreamEncoder struct {
	message int
	next    int
	calls   map[int]responsesStreamCall
}

type responsesStreamCall struct {
	outputIndex int
	id          string
}

// NewResponsesStreamEncoder returns an encoder for one Responses stream.
func NewResponsesStreamEncoder() *ResponsesStreamEncoder {
	return &ResponsesStreamEncoder{message: -1, calls: map[int]responsesStreamCall{}}
}

// Content encodes the role, text and tool-call deltas of chunk. The message
// item is added once, on the first role or text, since some upstreams such as
// Gemini repeat the role on every chunk; each tool call is added once, at the
// next free output_index, when its canonical index first appears or when a
// delta at that index carries a different call id.
func (e *ResponsesStreamEncoder) Content(chunk *CanonicalStreamChunk) [][]byte {
	var lines [][]byte
	if e.message < 0 && (chunk.Role != "" || chunk.Delta != "") {
		role := chunk.Role
		if role == "" {
			role = "assistant"
		}
		e.message = e.next
		e.next++
		lines = append(lines, responsesMessageAdded(e.message, role)...)
	}
	if chunk.Delta != "" {
		lines = append(lines, responsesTextDelta(e.message, chunk.Delta)...)
	}
	for _, tc := range chunk.ToolCallDeltas {
		call, ok := e.calls[tc.Index]
		if !ok || (tc.ID != "" && call.id != "" && tc.ID != call.id) {
			call = responsesStreamCall{outputIndex: e.next, id: tc.ID}
			e.next++
			e.calls[tc.Index] = call
			lines = append(lines, responsesFunctionCallAdded(call.outputIndex, tc)...)
		} else if call.id == "" && tc.ID != "" {
			call.id = tc.ID
			e.calls[tc.Index] = call
		}
		index := call.outputIndex
		if tc.ArgumentsDelta != "" {
			lines = append(lines, responsesArgumentsDelta(index, tc.ArgumentsDelta)...)
		}
	}
	return lines
}

// Finish encodes the finish and usage of chunk.
func (e *ResponsesStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	lines, _ := encodeResponsesStreamChunk(&CanonicalStreamChunk{
		ID:           chunk.ID,
		Model:        chunk.Model,
		FinishReason: chunk.FinishReason,
		Usage:        chunk.Usage,
	})
	return lines
}
