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
	"time"
)

const (
	responsesStatusInProgress = "in_progress"
	responsesStatusCompleted  = "completed"
	responsesStatusIncomplete = "incomplete"
	responsesItemMessage      = "message"
	responsesItemFunctionCall = "function_call"
	responsesOutputText       = "output_text"
)

// ResponsesStreamEncoder encodes a canonical stream as Responses API events, giving each item its own output_index; not safe for concurrent use.
type ResponsesStreamEncoder struct {
	nonce     string
	id        string
	model     string
	createdAt int64
	started   bool
	done      bool
	sequence  int
	items     []*responsesStreamItem
	message   *responsesStreamItem
	calls     map[int]*responsesStreamItem
	callIDs   map[string]bool
}

type responsesStreamItem struct {
	outputIndex int
	kind        string
	id          string
	callID      string
	name        string
	upstreamID  string
	text        strings.Builder
	announced   bool
}

// NewResponsesStreamEncoder returns an encoder for one Responses stream.
func NewResponsesStreamEncoder() *ResponsesStreamEncoder {
	return &ResponsesStreamEncoder{
		nonce:   rand.Text(),
		calls:   map[int]*responsesStreamItem{},
		callIDs: map[string]bool{},
	}
}

// Content encodes the text and tool-call deltas of chunk.
func (e *ResponsesStreamEncoder) Content(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	e.remember(chunk)
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

// Finish encodes the finish and usage of chunk.
func (e *ResponsesStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	e.remember(chunk)
	lines := e.start()
	e.done = true
	status := responsesStatusCompleted
	if chunk.FinishReason == "length" {
		status = responsesStatusIncomplete
	}
	output := make([]map[string]any, 0, len(e.items))
	for _, item := range e.items {
		lines = append(lines, e.finishItem(item, status)...)
		output = append(output, item.snapshot(status))
	}
	response := e.response(status)
	response["output"] = output
	if usage := openaiResponsesUsageFromCanonical(chunk.Usage); usage != nil {
		response["usage"] = usage
	}
	event := "response.completed"
	if status == responsesStatusIncomplete {
		event = "response.incomplete"
		response["incomplete_details"] = map[string]string{"reason": "max_output_tokens"}
	}
	return append(lines, e.event(event, map[string]any{"response": response})...)
}

func (e *ResponsesStreamEncoder) remember(chunk *CanonicalStreamChunk) {
	if e.id == "" && !e.started {
		e.id = chunk.ID
	}
	if e.model == "" {
		e.model = chunk.Model
	}
}

func (e *ResponsesStreamEncoder) start() [][]byte {
	if e.started {
		return nil
	}
	e.started = true
	if e.id == "" {
		e.id = "resp_" + e.nonce
	}
	e.createdAt = time.Now().Unix()
	lines := e.event("response.created", map[string]any{"response": e.response(responsesStatusInProgress)})
	return append(lines, e.event("response.in_progress", map[string]any{"response": e.response(responsesStatusInProgress)})...)
}

func (e *ResponsesStreamEncoder) response(status string) map[string]any {
	return map[string]any{
		"id":         e.id,
		"object":     "response",
		"created_at": e.createdAt,
		"status":     status,
		"model":      e.model,
		"output":     []any{},
	}
}

func (e *ResponsesStreamEncoder) textDelta(delta string) [][]byte {
	var lines [][]byte
	if e.message == nil {
		e.message = e.addItem(&responsesStreamItem{kind: responsesItemMessage, id: "msg_" + e.nonce})
		lines = e.event("response.output_item.added", map[string]any{
			"output_index": e.message.outputIndex,
			"item":         e.message.snapshot(responsesStatusInProgress),
		})
		lines = append(lines, e.event("response.content_part.added", map[string]any{
			"item_id":       e.message.id,
			"output_index":  e.message.outputIndex,
			"content_index": 0,
			"part":          responsesOutputTextPart(""),
		})...)
	}
	e.message.text.WriteString(delta)
	return append(lines, e.event("response.output_text.delta", map[string]any{
		"item_id":       e.message.id,
		"output_index":  e.message.outputIndex,
		"content_index": 0,
		"delta":         delta,
		"logprobs":      []any{},
	})...)
}

func (e *ResponsesStreamEncoder) toolDelta(tc StreamToolCallDelta) [][]byte {
	call := e.calls[tc.Index]
	if call == nil || (tc.ID != "" && call.upstreamID != "" && tc.ID != call.upstreamID) {
		call = &responsesStreamItem{kind: responsesItemFunctionCall, upstreamID: tc.ID, name: tc.Name}
		e.calls[tc.Index] = call
	} else {
		if call.upstreamID == "" {
			call.upstreamID = tc.ID
		}
		if call.name == "" {
			call.name = tc.Name
		}
	}
	if call.announced {
		if tc.ArgumentsDelta == "" {
			return nil
		}
		call.text.WriteString(tc.ArgumentsDelta)
		return e.argumentsDelta(call, tc.ArgumentsDelta)
	}
	call.text.WriteString(tc.ArgumentsDelta)
	if call.upstreamID == "" && call.name == "" {
		return nil
	}
	return e.announce(call)
}

func (e *ResponsesStreamEncoder) announce(call *responsesStreamItem) [][]byte {
	call.announced = true
	call.callID = e.callID(call.upstreamID)
	call.id = call.callID
	if !strings.HasPrefix(call.id, "fc_") {
		call.id = "fc_" + call.id
	}
	e.addItem(call)
	lines := e.event("response.output_item.added", map[string]any{
		"output_index": call.outputIndex,
		"item":         call.functionCall("", responsesStatusInProgress),
	})
	if call.text.Len() > 0 {
		lines = append(lines, e.argumentsDelta(call, call.text.String())...)
	}
	return lines
}

func (e *ResponsesStreamEncoder) callID(upstream string) string {
	id := upstream
	if id == "" || e.callIDs[id] {
		id = fmt.Sprintf("call_%s_%d", e.nonce, len(e.items))
	}
	e.callIDs[id] = true
	return id
}

func (e *ResponsesStreamEncoder) addItem(item *responsesStreamItem) *responsesStreamItem {
	item.outputIndex = len(e.items)
	e.items = append(e.items, item)
	return item
}

func (e *ResponsesStreamEncoder) argumentsDelta(call *responsesStreamItem, delta string) [][]byte {
	return e.event("response.function_call_arguments.delta", map[string]any{
		"item_id":      call.id,
		"output_index": call.outputIndex,
		"delta":        delta,
	})
}

func (e *ResponsesStreamEncoder) finishItem(item *responsesStreamItem, status string) [][]byte {
	text := item.text.String()
	var lines [][]byte
	if item.kind == responsesItemMessage {
		lines = e.event("response.output_text.done", map[string]any{
			"item_id":       item.id,
			"output_index":  item.outputIndex,
			"content_index": 0,
			"text":          text,
			"logprobs":      []any{},
		})
		lines = append(lines, e.event("response.content_part.done", map[string]any{
			"item_id":       item.id,
			"output_index":  item.outputIndex,
			"content_index": 0,
			"part":          responsesOutputTextPart(text),
		})...)
	} else {
		lines = e.event("response.function_call_arguments.done", map[string]any{
			"item_id":      item.id,
			"output_index": item.outputIndex,
			"arguments":    text,
		})
	}
	return append(lines, e.event("response.output_item.done", map[string]any{
		"output_index": item.outputIndex,
		"item":         item.snapshot(status),
	})...)
}

func (e *ResponsesStreamEncoder) event(eventType string, fields map[string]any) [][]byte {
	fields["type"] = eventType
	fields["sequence_number"] = e.sequence
	e.sequence++
	data, _ := json.Marshal(fields)
	return SSEEvent(eventType, data)
}

func (t *responsesStreamItem) snapshot(status string) map[string]any {
	if t.kind == responsesItemFunctionCall {
		arguments := ""
		if status != responsesStatusInProgress {
			arguments = t.text.String()
		}
		return t.functionCall(arguments, status)
	}
	content := []any{}
	if status != responsesStatusInProgress {
		content = append(content, responsesOutputTextPart(t.text.String()))
	}
	return map[string]any{
		"type":    responsesItemMessage,
		"id":      t.id,
		"role":    "assistant",
		"status":  status,
		"content": content,
	}
}

func (t *responsesStreamItem) functionCall(arguments, status string) map[string]any {
	return map[string]any{
		"type":      responsesItemFunctionCall,
		"id":        t.id,
		"call_id":   t.callID,
		"name":      t.name,
		"arguments": arguments,
		"status":    status,
	}
}

func responsesOutputTextPart(text string) map[string]any {
	return map[string]any{"type": responsesOutputText, "text": text, "annotations": []any{}}
}
