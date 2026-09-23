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
	"fmt"
	"strings"
)

const anthropicTruncatedToolCallMessage = "upstream tool call arguments could not be streamed intact"

// AnthropicStreamEncoder encodes one canonical stream as an Anthropic Messages
// event sequence: one message_start, content blocks started, filled and
// stopped one at a time in index order, then either message_delta and
// message_stop or an error event. Reasoning deltas are not emitted, since a
// thinking block cannot carry the signature Anthropic requires on replay.
// An AnthropicStreamEncoder is not safe for concurrent use.
type AnthropicStreamEncoder struct {
	completeToolCalls bool
	nonce             string
	id                string
	model             string
	started           bool
	done              bool
	aborted           bool
	usedTool          bool
	buffering         bool
	next              int
	open              int
	openType          anthropicBlockType
	openTool          *anthropicStreamTool
	tools             map[int]*anthropicStreamTool
	pending           []*anthropicStreamTool
	heldText          strings.Builder
	ids               map[string]bool
	droppedDeltas     int
	droppedTools      int
}

type anthropicStreamTool struct {
	upstreamID string
	name       string
	args       strings.Builder
	deltas     int
	streamed   bool
	checkedLen int
	valid      bool
}

// complete reports whether the arguments received so far are empty or form a
// JSON value, the only points at which the call's block can close without
// losing input: content_block_start already carries an empty input object.
func (t *anthropicStreamTool) complete() bool {
	if t.args.Len() == 0 {
		return true
	}
	if t.checkedLen != t.args.Len() {
		t.checkedLen = t.args.Len()
		t.valid = json.Valid([]byte(t.args.String()))
	}
	return t.valid
}

// NewAnthropicStreamEncoder returns an encoder for a stream whose upstream
// speaks target.
func NewAnthropicStreamEncoder(target Format) *AnthropicStreamEncoder {
	return &AnthropicStreamEncoder{
		completeToolCalls: IsSameWireFormat(target, FormatGemini),
		nonce:             rand.Text(),
		open:              -1,
		tools:             map[int]*anthropicStreamTool{},
		ids:               map[string]bool{},
	}
}

// Content encodes the role, text and tool call deltas of chunk; its finish
// reason is ignored. The first chunk with a role or content starts the message.
func (e *AnthropicStreamEncoder) Content(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	e.remember(chunk)
	if chunk.Role == "" && chunk.Delta == "" && len(chunk.ToolCallDeltas) == 0 {
		return nil
	}
	lines := e.start(chunk.Usage)
	if chunk.Delta != "" {
		lines = append(lines, e.textDelta(chunk.Delta)...)
	}
	for _, tc := range chunk.ToolCallDeltas {
		lines = append(lines, e.toolDelta(tc)...)
	}
	return lines
}

// Finish closes the open block, emits the text and tool calls held back, and
// ends the message with the stop_reason mapped from chunk.FinishReason and
// chunk.Usage. It aborts instead when the finish reason reports a failure (see
// FinishFailure) or when tool argument deltas were dropped. A max_tokens stop
// whose tool arguments are incomplete is passed through as max_tokens, as the
// native API does. Nothing is emitted once the stream has finished or aborted.
func (e *AnthropicStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	e.remember(chunk)
	lines := e.start(nil)
	if message, failed := FinishFailure(chunk.FinishReason); failed {
		return append(lines, e.Abort(message)...)
	}
	if e.droppedDeltas > 0 {
		return append(lines, e.Abort(anthropicTruncatedToolCallMessage)...)
	}
	lines = append(lines, e.releaseText()...)
	lines = append(lines, e.closeOpen()...)
	lines = append(lines, e.flushPending()...)
	e.done = true
	reason := chunk.FinishReason
	switch {
	case e.usedTool && reason == "stop":
		// Gemini reports STOP after a functionCall; Anthropic clients expect tool_use.
		reason = "tool_calls"
	case !e.usedTool && reason == "tool_calls":
		// Every tool call was dropped, so a tool_use stop would leave the client
		// waiting on a call it never received.
		reason = "stop"
	}
	return append(lines, anthropicMessageEndEvents(reason, chunk.Usage)...)
}

// Abort closes the open block and ends the stream with an api_error event
// carrying message. Text and tool calls held back are dropped. Nothing is emitted once
// the stream has finished or aborted.
func (e *AnthropicStreamEncoder) Abort(message string) [][]byte {
	if e.done {
		return nil
	}
	e.done = true
	e.aborted = true
	return append(e.closeOpen(), anthropicErrorEvent(message)...)
}

// Aborted reports whether the stream ended with an error event rather than
// message_stop.
func (e *AnthropicStreamEncoder) Aborted() bool {
	return e.aborted
}

// Dropped reports the tool argument deltas that arrived after their block
// stopped and the tool calls that never got a name, none of which reached the
// client.
func (e *AnthropicStreamEncoder) Dropped() (deltas, tools int) {
	return e.droppedDeltas, e.droppedTools
}

func (e *AnthropicStreamEncoder) remember(chunk *CanonicalStreamChunk) {
	if e.id == "" {
		e.id = chunk.ID
	}
	if e.model == "" {
		e.model = chunk.Model
	}
}

func (e *AnthropicStreamEncoder) start(usage *CanonicalUsage) [][]byte {
	if e.started {
		return nil
	}
	e.started = true
	id := e.id
	if id == "" {
		id = "msg_" + e.nonce
	}
	return anthropicMessageStartEvent(id, e.model, usage)
}

// textDelta holds text back while the open tool call's arguments are
// incomplete, since opening a text block would stop the call's block before
// its remaining arguments arrive.
func (e *AnthropicStreamEncoder) textDelta(text string) [][]byte {
	if e.openTool != nil && !e.openTool.complete() {
		e.heldText.WriteString(text)
		return nil
	}
	return e.emitText(e.takeHeldText() + text)
}

func (e *AnthropicStreamEncoder) releaseText() [][]byte {
	if e.heldText.Len() == 0 {
		return nil
	}
	return e.emitText(e.takeHeldText())
}

func (e *AnthropicStreamEncoder) takeHeldText() string {
	text := e.heldText.String()
	e.heldText.Reset()
	return text
}

func (e *AnthropicStreamEncoder) emitText(text string) [][]byte {
	var lines [][]byte
	if e.openType != anthropicBlockText {
		lines = e.openBlock(anthropicBlockText)
		lines = append(lines, anthropicTextBlockStartEvent(e.open)...)
	}
	return append(lines, anthropicContentBlockDeltaEvent(e.open, anthropicBlockText, text)...)
}

func (e *AnthropicStreamEncoder) toolDelta(tc StreamToolCallDelta) [][]byte {
	tool := e.tools[tc.Index]
	if tool == nil || e.startsNewCall(tc, tool) {
		tool = &anthropicStreamTool{upstreamID: tc.ID, name: tc.Name}
		e.tools[tc.Index] = tool
		e.pending = append(e.pending, tool)
	} else {
		if tool.upstreamID == "" {
			tool.upstreamID = tc.ID
		}
		if tool.name == "" {
			tool.name = tc.Name
		}
	}
	if tool == e.openTool {
		if len(e.pending) > 0 {
			e.buffering = true
		}
		if tc.ArgumentsDelta == "" {
			return nil
		}
		tool.args.WriteString(tc.ArgumentsDelta)
		return anthropicContentBlockDeltaEvent(e.open, anthropicBlockToolUse, tc.ArgumentsDelta)
	}
	if tool.streamed {
		// Its block is already stopped; Anthropic has no way to append to it.
		if tc.ArgumentsDelta != "" {
			e.droppedDeltas++
		}
		e.buffering = true
		return nil
	}
	tool.deltas++
	tool.args.WriteString(tc.ArgumentsDelta)
	return e.streamTool(tool)
}

func (e *AnthropicStreamEncoder) startsNewCall(tc StreamToolCallDelta, tool *anthropicStreamTool) bool {
	if tc.ID == "" && tc.Name == "" {
		return false
	}
	return e.completeToolCalls || (tc.ID != "" && tool.upstreamID != "" && tc.ID != tool.upstreamID)
}

// streamTool opens tool's block when it can stream without interleaving with
// another tool call; once calls interleave, every remaining one is held for
// Finish. A call that follows an open one waits for its second delta: a delta
// for the open call in between reveals an interleave, while two in a row
// suggest the open call is done. The open call's block only stops once its
// arguments are complete JSON; until then the new call is held for Finish too.
// Gemini calls arrive whole, so they never wait.
func (e *AnthropicStreamEncoder) streamTool(tool *anthropicStreamTool) [][]byte {
	if tool.name == "" || e.buffering {
		return nil
	}
	if e.pending[0] != tool {
		e.buffering = true
		return nil
	}
	if e.openTool != nil {
		if !e.completeToolCalls && tool.deltas < 2 {
			return nil
		}
		if !e.openTool.complete() {
			e.buffering = true
			return nil
		}
	}
	e.pending = e.pending[1:]
	lines := e.releaseText()
	lines = append(lines, e.openToolBlock(tool)...)
	e.openTool = tool
	return lines
}

func (e *AnthropicStreamEncoder) flushPending() [][]byte {
	var lines [][]byte
	for _, tool := range e.pending {
		if tool.name == "" {
			e.droppedTools++
			continue
		}
		lines = append(lines, e.openToolBlock(tool)...)
		lines = append(lines, e.closeOpen()...)
	}
	e.pending = nil
	return lines
}

func (e *AnthropicStreamEncoder) openToolBlock(tool *anthropicStreamTool) [][]byte {
	lines := e.openBlock(anthropicBlockToolUse)
	tool.streamed = true
	e.usedTool = true
	lines = append(lines, anthropicToolUseBlockStartEvent(e.open, e.toolID(tool.upstreamID), tool.name)...)
	if tool.args.Len() > 0 {
		lines = append(lines, anthropicContentBlockDeltaEvent(e.open, anthropicBlockToolUse, tool.args.String())...)
	}
	return lines
}

// toolID keeps the upstream id unless it is empty or already used, as Gemini
// reuses the function name as the id of every call to it.
func (e *AnthropicStreamEncoder) toolID(upstream string) string {
	id := upstream
	if id == "" || e.ids[id] {
		id = fmt.Sprintf("toolu_%s_%d", e.nonce, e.open)
	}
	e.ids[id] = true
	return id
}

func (e *AnthropicStreamEncoder) openBlock(block anthropicBlockType) [][]byte {
	lines := e.closeOpen()
	e.open = e.next
	e.openType = block
	e.next++
	return lines
}

func (e *AnthropicStreamEncoder) closeOpen() [][]byte {
	if e.open < 0 {
		return nil
	}
	index := e.open
	e.open = -1
	e.openType = ""
	e.openTool = nil
	return anthropicContentBlockStopEvent(index)
}
