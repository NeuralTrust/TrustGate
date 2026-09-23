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

// CohereStreamEncoder encodes a canonical stream as a Cohere v2 chat event sequence; not safe for concurrent use.
type CohereStreamEncoder struct {
	completeToolCalls bool
	nonce             string
	id                string
	started           bool
	done              bool
	aborted           bool
	usedTool          bool
	content           int
	nextContent       int
	nextTool          int
	arrivals          int
	chunks            int
	open              *cohereStreamTool
	tools             map[int]*cohereStreamTool
	ids               map[string]bool
	heldText          []cohereHeldText
	droppedDeltas     int
	droppedTools      int
}

type cohereStreamTool struct {
	id         string
	name       string
	args       strings.Builder
	arrival    int
	chunk      int
	started    bool
	ended      bool
	superseded bool
	checkedLen int
	valid      bool
}

type cohereHeldText struct {
	arrival int
	text    strings.Builder
}

// complete reports whether t's arguments are whole. A call without arguments
// is whole once another call starts in a later chunk, since a zero-argument
// call sends none; calls announced together fill their arguments in later.
func (t *cohereStreamTool) complete() bool {
	if t.args.Len() == 0 {
		return t.superseded
	}
	if t.checkedLen != t.args.Len() {
		t.checkedLen = t.args.Len()
		t.valid = json.Valid([]byte(t.args.String()))
	}
	return t.valid
}

// NewCohereStreamEncoder returns an encoder for the given target format.
func NewCohereStreamEncoder(target Format) *CohereStreamEncoder {
	return &CohereStreamEncoder{
		completeToolCalls: IsSameWireFormat(target, FormatGemini),
		nonce:             rand.Text(),
		content:           -1,
		tools:             map[int]*cohereStreamTool{},
		ids:               map[string]bool{},
	}
}

// Content encodes the role, text, and tool call deltas of chunk.
func (e *CohereStreamEncoder) Content(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	if e.id == "" {
		e.id = chunk.ID
	}
	if chunk.Role == "" && chunk.Delta == "" && len(chunk.ToolCallDeltas) == 0 {
		return nil
	}
	e.chunks++
	lines := e.start()
	if chunk.Delta != "" {
		lines = append(lines, e.textDelta(chunk.Delta)...)
	}
	for _, tc := range chunk.ToolCallDeltas {
		lines = append(lines, e.toolDelta(tc)...)
	}
	return lines
}

// Finish ends the message with the finish reason and usage from chunk, followed
// by the [DONE] a Cohere stream closes with.
func (e *CohereStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	if e.id == "" {
		e.id = chunk.ID
	}
	lines := e.start()
	lines = append(lines, e.releaseHeld(true)...)
	lines = append(lines, e.closeTool()...)
	lines = append(lines, e.closeContent()...)
	for _, tool := range e.tools {
		if !tool.started {
			e.droppedTools++
		}
	}
	e.done = true
	reason, errMessage := cohereStreamFinishReason(chunk.FinishReason, e.usedTool)
	lines = append(lines, cohereMessageEnd(reason, errMessage, chunk.Usage)...)
	return append(lines, SSEData([]byte("[DONE]"))...)
}

// Abort ends the message with an ERROR finish carrying message and usage,
// followed by [DONE], after closing the open content or tool call. Text and
// tool calls held back are dropped. Nothing is emitted once the stream has
// finished or aborted.
func (e *CohereStreamEncoder) Abort(message string, usage *CanonicalUsage) [][]byte {
	if e.done {
		return nil
	}
	lines := e.start()
	lines = append(lines, e.closeTool()...)
	lines = append(lines, e.closeContent()...)
	e.done = true
	e.aborted = true
	lines = append(lines, cohereMessageEnd("ERROR", message, usage)...)
	return append(lines, SSEData([]byte("[DONE]"))...)
}

// Aborted reports whether the stream ended with Abort rather than Finish.
func (e *CohereStreamEncoder) Aborted() bool {
	return e.aborted
}

// Started reports whether the client has been sent message-start.
func (e *CohereStreamEncoder) Started() bool {
	return e.started
}

// Dropped reports dropped tool call deltas and nameless tool calls.
func (e *CohereStreamEncoder) Dropped() (deltas, tools int) {
	return e.droppedDeltas, e.droppedTools
}

func cohereStreamFinishReason(reason string, usedTool bool) (string, string) {
	switch {
	case usedTool && reason == "stop":
		return "TOOL_CALL", ""
	case !usedTool && reason == "tool_calls":
		return "COMPLETE", ""
	default:
		return cohereFinish(reason)
	}
}

func (e *CohereStreamEncoder) start() [][]byte {
	if e.started {
		return nil
	}
	e.started = true
	id := e.id
	if id == "" {
		id = "msg_" + e.nonce
	}
	return cohereMessageStart(id)
}

func (e *CohereStreamEncoder) textDelta(text string) [][]byte {
	lines := e.releaseHeld(false)
	if e.open != nil && !e.toolComplete(e.open) {
		e.holdText(text)
		return lines
	}
	return append(lines, e.emitText(text)...)
}

func (e *CohereStreamEncoder) holdText(text string) {
	if n := len(e.heldText); n > 0 && e.heldText[n-1].arrival == e.arrivals-1 {
		e.heldText[n-1].text.WriteString(text)
		return
	}
	e.heldText = append(e.heldText, cohereHeldText{arrival: e.arrivals})
	e.heldText[len(e.heldText)-1].text.WriteString(text)
	e.arrivals++
}

func (e *CohereStreamEncoder) emitText(text string) [][]byte {
	lines := e.closeTool()
	if e.content < 0 {
		e.content = e.nextContent
		e.nextContent++
		lines = append(lines, cohereContentStart(e.content)...)
	}
	return append(lines, cohereContentDeltaEvent(e.content, text)...)
}

func (e *CohereStreamEncoder) toolDelta(tc StreamToolCallDelta) [][]byte {
	tool := e.tools[tc.Index]
	if tool == nil || e.startsNewCall(tc, tool) {
		if tool != nil && !tool.started {
			e.droppedTools++
		}
		if e.open != nil && e.open.args.Len() == 0 && e.open.chunk != e.chunks {
			e.open.superseded = true
		}
		tool = &cohereStreamTool{id: tc.ID, name: tc.Name, arrival: e.arrivals, chunk: e.chunks}
		e.arrivals++
		e.tools[tc.Index] = tool
	} else {
		if tool.id == "" {
			tool.id = tc.ID
		}
		if tool.name == "" {
			tool.name = tc.Name
		}
	}
	if tool.ended {
		if tc.ArgumentsDelta != "" {
			e.droppedDeltas++
		}
		return nil
	}
	if tool == e.open {
		if tc.ArgumentsDelta == "" {
			return nil
		}
		tool.args.WriteString(tc.ArgumentsDelta)
		return append(cohereToolCallDeltaEvent(e.nextTool-1, tc.ArgumentsDelta), e.releaseHeld(false)...)
	}
	tool.args.WriteString(tc.ArgumentsDelta)
	return e.releaseHeld(false)
}

// releaseHeld emits the held text and starts the named tool calls not yet
// started, in arrival order, while the open call's arguments are complete, or
// all of them when all is set: a Cohere client gets one call at a time, so
// what arrives while a call is still streaming its arguments waits for it
// instead of cutting it short.
func (e *CohereStreamEncoder) releaseHeld(all bool) [][]byte {
	var lines [][]byte
	for all || e.open == nil || e.toolComplete(e.open) {
		tool := e.nextHeld()
		if len(e.heldText) > 0 && (tool == nil || e.heldText[0].arrival < tool.arrival) {
			text := e.heldText[0].text.String()
			e.heldText = e.heldText[1:]
			lines = append(lines, e.emitText(text)...)
			continue
		}
		if tool == nil {
			break
		}
		lines = append(lines, e.startTool(tool)...)
	}
	return lines
}

func (e *CohereStreamEncoder) nextHeld() *cohereStreamTool {
	var next *cohereStreamTool
	nextIndex := 0
	for index, tool := range e.tools {
		if tool.name == "" || tool.started || tool.ended {
			continue
		}
		if next == nil || index < nextIndex {
			next, nextIndex = tool, index
		}
	}
	return next
}

// toolComplete reports whether t's arguments are whole. Calls from an upstream
// that sends each call complete in one chunk always are.
func (e *CohereStreamEncoder) toolComplete(t *cohereStreamTool) bool {
	return e.completeToolCalls || t.complete()
}

func (e *CohereStreamEncoder) startsNewCall(tc StreamToolCallDelta, tool *cohereStreamTool) bool {
	if tc.ID == "" && tc.Name == "" {
		return false
	}
	return e.completeToolCalls || (tc.ID != "" && tool.id != "" && tc.ID != tool.id)
}

func (e *CohereStreamEncoder) startTool(tool *cohereStreamTool) [][]byte {
	lines := e.closeTool()
	lines = append(lines, e.closeContent()...)
	index := e.nextTool
	e.nextTool++
	tool.started = true
	e.open = tool
	e.usedTool = true
	lines = append(lines, cohereToolCallStart(index, e.toolID(tool.id, index), tool.name)...)
	if tool.args.Len() > 0 {
		lines = append(lines, cohereToolCallDeltaEvent(index, tool.args.String())...)
	}
	return lines
}

func (e *CohereStreamEncoder) toolID(upstream string, index int) string {
	id := upstream
	if id == "" || e.ids[id] {
		id = fmt.Sprintf("call_%s_%d", e.nonce, index)
	}
	e.ids[id] = true
	return id
}

func (e *CohereStreamEncoder) closeTool() [][]byte {
	if e.open == nil {
		return nil
	}
	index := e.nextTool - 1
	var lines [][]byte
	if e.open.args.Len() == 0 {
		lines = cohereToolCallDeltaEvent(index, "{}")
	}
	e.open.ended = true
	e.open = nil
	return append(lines, cohereToolCallEnd(index)...)
}

func (e *CohereStreamEncoder) closeContent() [][]byte {
	if e.content < 0 {
		return nil
	}
	index := e.content
	e.content = -1
	return cohereContentEnd(index)
}
