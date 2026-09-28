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
	"encoding/json"
	"strings"
)

// GeminiStreamEncoder encodes a canonical stream for a Gemini client. Gemini
// has no argument deltas: every functionCall part carries its whole args, and
// a client takes each part as a complete call. Tool calls are therefore held
// per canonical index and sent once they are closed, in arrival order: in one
// chunk ahead of the text that follows them, or ahead of the finish.
//
// A held call is sent only when its arguments are empty or a JSON object, and
// only if the upstream finished normally: a length, context window or content
// filter stop, a failure finish, or an upstream that ended or failed without a
// finish may have cut the arguments short, and a client executes the calls it
// gets, so those calls are withheld, as the Responses encoder withholds them.
// A call that never got a name is dropped. It is not safe for concurrent use.
type GeminiStreamEncoder struct {
	codec     GeminiAdapter
	done      bool
	failed    bool
	calls     map[int]*geminiStreamCall
	pending   []*geminiStreamCall
	dropped   int
	withheld  int
	encodeErr error
}

type geminiStreamCall struct {
	id   string
	name string
	args strings.Builder
}

// complete reports whether c's arguments can be sent as functionCall args.
func (c *geminiStreamCall) complete() bool {
	if c.args.Len() == 0 {
		return true
	}
	var args map[string]any
	return json.Unmarshal([]byte(c.args.String()), &args) == nil && args != nil
}

// NewGeminiStreamEncoder returns an encoder for one Gemini stream.
func NewGeminiStreamEncoder() *GeminiStreamEncoder {
	return &GeminiStreamEncoder{calls: map[int]*geminiStreamCall{}}
}

// Content encodes the role and text of chunk and holds its tool-call deltas.
// Text closes the calls held before it, which are sent first.
func (e *GeminiStreamEncoder) Content(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	var lines [][]byte
	if chunk.Delta != "" {
		lines = e.sendCalls()
	}
	if chunk.Role != "" || chunk.Delta != "" {
		lines = append(lines, e.encode(&CanonicalStreamChunk{Role: chunk.Role, Delta: chunk.Delta})...)
	}
	for _, tc := range chunk.ToolCallDeltas {
		e.toolDelta(tc)
	}
	return lines
}

// Finish sends the held tool calls, unless the finish reason says their
// arguments may be cut short, then the finish and usage of chunk.
func (e *GeminiStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	e.done = true
	var lines [][]byte
	if _, failed := FinishFailure(chunk.FinishReason); failed || truncatedFinish(chunk.FinishReason) || refusalFinish(chunk.FinishReason) {
		e.withhold()
	} else {
		lines = e.sendCalls()
	}
	return append(lines, e.encode(chunk)...)
}

// Abort ends the stream of an upstream that ended without a finish: the held
// tool calls are withheld and nothing more is sent.
func (e *GeminiStreamEncoder) Abort() {
	if e.done {
		return
	}
	e.done = true
	e.withhold()
}

// Fail ends the stream of an upstream that failed before its finish: the held
// tool calls are withheld and the client gets the error object the Gemini API
// sends mid-stream, with an INTERNAL status and code 500, which Gemini SDKs
// raise as a server error. Nothing is sent once the stream has ended.
func (e *GeminiStreamEncoder) Fail(message string) [][]byte {
	if e.done {
		return nil
	}
	e.done = true
	e.failed = true
	e.withhold()
	data, err := json.Marshal(geminiStreamError{Error: geminiStreamErrorBody{
		Code:    geminiErrorCode,
		Message: message,
		Status:  geminiErrorStatus,
	}})
	if err != nil {
		e.encodeErr = err
		return nil
	}
	return SSEData(data)
}

// Failed reports whether the client got an error object from Fail.
func (e *GeminiStreamEncoder) Failed() bool {
	return e.failed
}

// TakeEncodeError returns the error of the last chunk that could not be
// encoded since the previous call, and clears it. That chunk was not sent.
func (e *GeminiStreamEncoder) TakeEncodeError() error {
	err := e.encodeErr
	e.encodeErr = nil
	return err
}

// HeldCallsComplete reports whether every named tool call held back has
// arguments that can be sent. It is asked of an upstream that sent [DONE]
// without a finish, which leaves no other sign that a call was cut short. As
// in ResponsesStreamEncoder.HeldCallsComplete, a call with no argument bytes
// counts as complete and is sent with {}: OpenAI-compatible upstreams stream
// a call to a tool that takes no arguments that way, and a call cut before
// its first argument delta cannot be told apart from it.
func (e *GeminiStreamEncoder) HeldCallsComplete() bool {
	for _, call := range e.pending {
		if call.name != "" && !call.complete() {
			return false
		}
	}
	return true
}

// Dropped reports the tool calls the client never got because they never got
// a name.
func (e *GeminiStreamEncoder) Dropped() int {
	return e.dropped
}

// Withheld reports the named tool calls the client never got because their
// arguments were not a JSON object or the stream did not finish normally.
func (e *GeminiStreamEncoder) Withheld() int {
	return e.withheld
}

func (e *GeminiStreamEncoder) toolDelta(tc StreamToolCallDelta) {
	call := e.calls[tc.Index]
	if call == nil || (tc.ID != "" && call.id != "" && tc.ID != call.id) {
		call = &geminiStreamCall{id: tc.ID, name: tc.Name}
		e.calls[tc.Index] = call
		e.pending = append(e.pending, call)
	} else {
		if call.id == "" {
			call.id = tc.ID
		}
		if call.name == "" {
			call.name = tc.Name
		}
	}
	call.args.WriteString(tc.ArgumentsDelta)
}

func (e *GeminiStreamEncoder) sendCalls() [][]byte {
	deltas := make([]StreamToolCallDelta, 0, len(e.pending))
	for _, call := range e.pending {
		switch {
		case call.name == "":
			e.dropped++
		case !call.complete():
			e.withheld++
		default:
			deltas = append(deltas, StreamToolCallDelta{
				Index:          len(deltas),
				ID:             call.id,
				Name:           call.name,
				ArgumentsDelta: call.args.String(),
			})
		}
	}
	e.reset()
	if len(deltas) == 0 {
		return nil
	}
	return e.encode(&CanonicalStreamChunk{ToolCallDeltas: deltas})
}

func (e *GeminiStreamEncoder) withhold() {
	for _, call := range e.pending {
		if call.name == "" {
			e.dropped++
			continue
		}
		e.withheld++
	}
	e.reset()
}

func (e *GeminiStreamEncoder) reset() {
	e.pending = nil
	clear(e.calls)
}

func (e *GeminiStreamEncoder) encode(chunk *CanonicalStreamChunk) [][]byte {
	lines, err := e.codec.EncodeStreamChunk(chunk)
	if err != nil {
		e.encodeErr = err
		return nil
	}
	return lines
}

const (
	geminiErrorCode   = 500
	geminiErrorStatus = "INTERNAL"
)

type geminiStreamError struct {
	Error geminiStreamErrorBody `json:"error"`
}

type geminiStreamErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}
