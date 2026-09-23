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
	usedTool          bool
	content           int
	nextContent       int
	nextTool          int
	open              *cohereStreamTool
	tools             map[int]*cohereStreamTool
	ids               map[string]bool
	heldText          strings.Builder
	droppedDeltas     int
	droppedTools      int
}

type cohereStreamTool struct {
	id         string
	name       string
	args       strings.Builder
	started    bool
	ended      bool
	checkedLen int
	valid      bool
}

func (t *cohereStreamTool) complete() bool {
	if t.args.Len() == 0 {
		return true
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
	lines := e.start()
	if chunk.Delta != "" {
		lines = append(lines, e.textDelta(chunk.Delta)...)
	}
	for _, tc := range chunk.ToolCallDeltas {
		lines = append(lines, e.toolDelta(tc)...)
	}
	return lines
}

// Finish ends the message with finish reason and usage from chunk.
func (e *CohereStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	if e.id == "" {
		e.id = chunk.ID
	}
	lines := e.start()
	lines = append(lines, e.closeTool()...)
	lines = append(lines, e.releaseText()...)
	lines = append(lines, e.closeContent()...)
	for _, tool := range e.tools {
		if !tool.started {
			e.droppedTools++
		}
	}
	e.done = true
	return append(lines, cohereMessageEnd(cohereStreamFinishReason(chunk.FinishReason, e.usedTool), chunk.Usage)...)
}

// Dropped reports dropped tool call deltas and nameless tool calls.
func (e *CohereStreamEncoder) Dropped() (deltas, tools int) {
	return e.droppedDeltas, e.droppedTools
}

func cohereStreamFinishReason(reason string, usedTool bool) string {
	if _, failed := FinishFailure(reason); failed {
		return "ERROR"
	}
	switch {
	case usedTool && reason == "stop":
		return "TOOL_CALL"
	case !usedTool && reason == "tool_calls":
		return "COMPLETE"
	default:
		return canonicalFinishToCohere(reason)
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
	if e.open != nil && !e.open.complete() {
		e.heldText.WriteString(text)
		return nil
	}
	return e.emitText(e.takeHeldText() + text)
}

func (e *CohereStreamEncoder) releaseText() [][]byte {
	if e.heldText.Len() == 0 {
		return nil
	}
	return e.emitText(e.takeHeldText())
}

func (e *CohereStreamEncoder) takeHeldText() string {
	text := e.heldText.String()
	e.heldText.Reset()
	return text
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
		tool = &cohereStreamTool{id: tc.ID, name: tc.Name}
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
		return cohereToolCallDeltaEvent(e.nextTool-1, tc.ArgumentsDelta)
	}
	tool.args.WriteString(tc.ArgumentsDelta)
	if tool.name == "" {
		return nil
	}
	return e.startTool(tool)
}

func (e *CohereStreamEncoder) startsNewCall(tc StreamToolCallDelta, tool *cohereStreamTool) bool {
	if tc.ID == "" && tc.Name == "" {
		return false
	}
	return e.completeToolCalls || (tc.ID != "" && tool.id != "" && tc.ID != tool.id)
}

func (e *CohereStreamEncoder) startTool(tool *cohereStreamTool) [][]byte {
	lines := e.closeTool()
	lines = append(lines, e.releaseText()...)
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
	e.open.ended = true
	e.open = nil
	return cohereToolCallEnd(e.nextTool - 1)
}

func (e *CohereStreamEncoder) closeContent() [][]byte {
	if e.content < 0 {
		return nil
	}
	index := e.content
	e.content = -1
	return cohereContentEnd(index)
}
