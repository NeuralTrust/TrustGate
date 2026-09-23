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
	responsesStatusFailed     = "failed"
	responsesErrorCode        = "server_error"
	responsesItemMessage      = "message"
	responsesItemFunctionCall = "function_call"
	responsesOutputText       = "output_text"
	responsesEmptyArguments   = "{}"
)

// responsesKeepaliveInterval bounds how long a Responses client goes without
// bytes while calls are held or reasoning is not forwarded: load balancer and
// CDN idle timeouts (60s on an ALB, 100s on Cloudflare) cut quieter streams.
const responsesKeepaliveInterval = 10 * time.Second

// ResponsesStreamEncoder encodes a canonical stream as Responses API events.
// Items go out one at a time, each with its own output_index: the text
// streams live as a single message and the tool calls are held until Finish,
// where they always follow the message in arrival order, whatever order the
// upstream interleaved text and calls in. It is not safe for concurrent use.
type ResponsesStreamEncoder struct {
	now       func() time.Time
	lastSent  time.Time
	nonce     string
	id        string
	model     string
	createdAt int64
	started   bool
	done      bool
	aborted   bool
	dropped   int
	withheld  int
	sequence  int
	items     []*responsesStreamItem
	message   *responsesStreamItem
	calls     map[int]*responsesStreamItem
	pending   []*responsesStreamItem
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
}

// ResponsesStreamOption configures a ResponsesStreamEncoder.
type ResponsesStreamOption func(*ResponsesStreamEncoder)

// WithResponsesClock makes the encoder read the time from now instead of
// time.Now.
func WithResponsesClock(now func() time.Time) ResponsesStreamOption {
	return func(e *ResponsesStreamEncoder) {
		e.now = now
	}
}

// NewResponsesStreamEncoder returns an encoder for one Responses stream.
func NewResponsesStreamEncoder(opts ...ResponsesStreamOption) *ResponsesStreamEncoder {
	e := &ResponsesStreamEncoder{
		now:     time.Now,
		nonce:   rand.Text(),
		calls:   map[int]*responsesStreamItem{},
		callIDs: map[string]bool{},
	}
	for _, opt := range opts {
		opt(e)
	}
	e.lastSent = e.now()
	return e
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
		e.toolDelta(tc)
	}
	return lines
}

// Finish encodes the finish and usage of chunk: response.completed, or
// response.incomplete for a length or content filter stop. The held tool
// calls follow the message on response.completed only: the arguments of an
// incomplete response may be cut short, and clients execute the calls they
// get, so those calls are withheld. A finish reason reporting a failure (see
// FinishFailure) ends the stream as Abort does.
func (e *ResponsesStreamEncoder) Finish(chunk *CanonicalStreamChunk) [][]byte {
	if e.done {
		return nil
	}
	e.remember(chunk)
	lines := e.start()
	if message, failed := FinishFailure(chunk.FinishReason); failed {
		return append(lines, e.fail(message, chunk.Usage)...)
	}
	e.done = true
	status, reason := responsesFinishStatus(chunk.FinishReason)
	lines = append(lines, e.finishMessage(status)...)
	calls := e.namedCalls()
	if status == responsesStatusIncomplete {
		e.withheld += len(calls)
		calls = nil
	}
	for _, call := range calls {
		lines = append(lines, e.emitCall(call)...)
	}
	response := e.terminalResponse(status, chunk.Usage)
	event := "response.completed"
	if status == responsesStatusIncomplete {
		event = "response.incomplete"
		response["incomplete_details"] = map[string]string{"reason": reason}
	}
	return append(lines, e.event(event, map[string]any{"response": response})...)
}

// Abort ends a started stream with an error event carrying message, then
// response.failed with usage. The message is marked incomplete and the tool
// calls held back are withheld, so response.failed lists only the items the
// client saw. Nothing is emitted before response.created or once the stream
// has ended.
func (e *ResponsesStreamEncoder) Abort(message string, usage *CanonicalUsage) [][]byte {
	if e.done || !e.started {
		return nil
	}
	return e.fail(message, usage)
}

// Started reports whether the client has been sent response.created.
func (e *ResponsesStreamEncoder) Started() bool {
	return e.started
}

// Aborted reports whether the stream ended with response.failed.
func (e *ResponsesStreamEncoder) Aborted() bool {
	return e.aborted
}

// Dropped reports the tool calls the client never got because they never
// got a name.
func (e *ResponsesStreamEncoder) Dropped() int {
	return e.dropped
}

// Withheld reports the named tool calls the client never got because the
// stream ended incomplete or failed.
func (e *ResponsesStreamEncoder) Withheld() int {
	return e.withheld
}

// Keepalive returns an SSE comment line once the open stream has sent the
// client nothing for responsesKeepaliveInterval, and nothing otherwise. SSE
// clients skip comments, so it only keeps idle timeouts from cutting a
// stream whose calls are held or whose reasoning is not forwarded.
func (e *ResponsesStreamEncoder) Keepalive() [][]byte {
	if e.done {
		return nil
	}
	now := e.now()
	if now.Sub(e.lastSent) < responsesKeepaliveInterval {
		return nil
	}
	e.lastSent = now
	return [][]byte{[]byte(": keepalive"), {}}
}

func responsesFinishStatus(reason string) (status, incompleteReason string) {
	switch {
	case reason == "length":
		return responsesStatusIncomplete, "max_output_tokens"
	case refusalFinish(reason):
		return responsesStatusIncomplete, "content_filter"
	default:
		return responsesStatusCompleted, ""
	}
}

func (e *ResponsesStreamEncoder) fail(message string, usage *CanonicalUsage) [][]byte {
	e.done = true
	e.aborted = true
	e.withheld += len(e.namedCalls())
	lines := e.finishMessage(responsesStatusIncomplete)
	lines = append(lines, e.event("error", map[string]any{
		"code":    responsesErrorCode,
		"message": message,
		"param":   nil,
	})...)
	response := e.terminalResponse(responsesStatusIncomplete, usage)
	response["status"] = responsesStatusFailed
	response["error"] = map[string]string{"code": responsesErrorCode, "message": message}
	return append(lines, e.event("response.failed", map[string]any{"response": response})...)
}

func (e *ResponsesStreamEncoder) finishMessage(status string) [][]byte {
	if e.message == nil {
		return nil
	}
	lines := e.finishItem(e.message, status)
	e.message = nil
	return lines
}

func (e *ResponsesStreamEncoder) namedCalls() []*responsesStreamItem {
	named := make([]*responsesStreamItem, 0, len(e.pending))
	for _, call := range e.pending {
		if call.name == "" {
			e.dropped++
			continue
		}
		named = append(named, call)
	}
	e.pending = nil
	return named
}

func (e *ResponsesStreamEncoder) terminalResponse(itemStatus string, usage *CanonicalUsage) map[string]any {
	output := make([]map[string]any, 0, len(e.items))
	for _, item := range e.items {
		output = append(output, item.snapshot(itemStatus))
	}
	response := e.response(itemStatus)
	response["output"] = output
	if u := openaiResponsesUsageFromCanonical(usage); u != nil {
		response["usage"] = u
	}
	return response
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
	e.createdAt = e.now().Unix()
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

// toolDelta holds the call back until Finish. LangChain numbers content
// blocks by output_index changes, so a call left open while text or another
// call streams comes back as tool calls with no name or id, and an
// output_text.done that arrives after output_index moved on becomes an empty
// message block that DeepSeek and Cohere reject (ENG-1618).
func (e *ResponsesStreamEncoder) toolDelta(tc StreamToolCallDelta) {
	call := e.calls[tc.Index]
	if call == nil || (tc.ID != "" && call.upstreamID != "" && tc.ID != call.upstreamID) {
		call = &responsesStreamItem{kind: responsesItemFunctionCall, upstreamID: tc.ID, name: tc.Name}
		e.calls[tc.Index] = call
		e.pending = append(e.pending, call)
	} else {
		if call.upstreamID == "" {
			call.upstreamID = tc.ID
		}
		if call.name == "" {
			call.name = tc.Name
		}
	}
	call.text.WriteString(tc.ArgumentsDelta)
}

func (e *ResponsesStreamEncoder) emitCall(call *responsesStreamItem) [][]byte {
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
	if call.text.Len() == 0 {
		call.text.WriteString(responsesEmptyArguments)
	}
	lines = append(lines, e.argumentsDelta(call, call.text.String())...)
	return append(lines, e.finishItem(call, responsesStatusCompleted)...)
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
	e.lastSent = e.now()
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
