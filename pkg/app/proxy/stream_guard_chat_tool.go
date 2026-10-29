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

package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"slices"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type chatToolKey struct {
	choice int
	index  int
}

type chatToolName struct {
	id   string
	name string
}

// chatCompletionsWire reports a source whose tool calls arrive as
// tool_calls[i] argument deltas with no frame of their own to open or close
// them.
func chatCompletionsWire(f adapter.Format) bool {
	return adapter.IsSameWireFormat(f, adapter.FormatOpenAI) || f == adapter.FormatMistral
}

// chatTools reports whether the guard holds chat-completions tool calls whole.
// Only a chain that reads tool calls asks for it (holdChatTools): otherwise the
// argument deltas reach the client as they arrive.
func (g *streamGuard) chatTools() bool {
	return g.chatHold && !g.native
}

// trackChatTool opens a tool call on its first tool_calls delta and closes it
// on the finish reason or any other terminal event, or on text or reasoning
// after it. Deltas of other indexes of the same choice keep it open, so
// interleaved calls are held together until all of them are whole.
//
// A second choice is refused (noteChatChoice), not held, including a second
// choice in the same chunk and a choice index that is not a JSON integer.
// The decoder reads choices[0] only, so either chunk would otherwise leave
// with tool calls the guard never saw. Holding each choice on its own would
// still be wrong: toolCallDigest merges by tool index alone, so two choices
// that both use index 0 become one arguments string, and a finish_reason on
// one choice is the stream's terminal event, which releases whatever the
// other choice still had open. The refusal runs before any of those bytes
// are released.
func (g *streamGuard) trackChatTool(ev *streamEvent) {
	g.noteChatChoice(ev)
	g.checkToolNames(ev)
	if g.toolOpen {
		switch {
		case ev.unit == unitTerminal,
			ev.choice >= 0 && ev.choice != g.toolChoice,
			len(ev.toolCalls) == 0 && (ev.text != "" || ev.reasoning != ""):
			g.toolOpen = false
		}
	}
	if g.toolOpen || ev.unit == unitTerminal || len(ev.toolCalls) == 0 {
		return
	}
	g.toolOpen, g.toolOpenIdx, g.toolSince, g.toolChoice = true, ev.toolCalls[0].Index, g.now(), ev.choice
}

// noteChatChoice records the choice indexes of the stream. More than one, in
// one chunk or across the stream, is refused, and so is a chunk whose index
// is not a JSON integer: see trackChatTool.
func (g *streamGuard) noteChatChoice(ev *streamEvent) {
	switch {
	case ev.choiceMany:
		g.toolMultiChoice = true
		return
	case ev.choiceBad:
		g.toolChoiceUnread = true
		return
	case !ev.choiceSet:
		return
	}
	if g.chatSeen == nil {
		g.chatSeen = map[int]struct{}{}
	}
	g.chatSeen[ev.choice] = struct{}{}
	if len(g.chatSeen) > 1 {
		g.toolMultiChoice = true
	}
}

// refusedChatTool reports a tool stream the guard will not release: a call
// whose name changed, arguments a boundary event disagrees with, more than
// one choice, or a choice index that could not be read. Each is a cut,
// whichever way on_error is set. The cap is a separate decision
// (chatToolCapped). Name and argument checks cover native SSE tool calls as
// well as chat completions.
func (g *streamGuard) refusedChatTool() (string, bool) {
	switch {
	case g.toolRenamed:
		return streamToolRenamedMessage, true
	case g.toolArgsMismatch:
		return streamToolArgsMessage, true
	case g.toolMultiChoice:
		return streamToolMultiChoiceMessage, true
	case g.toolChoiceUnread:
		return streamToolChoiceUnreadMessage, true
	default:
		return "", false
	}
}

// checkToolNames records the name each call opened with. The segments carry
// the latest name of a call, so a later delta that names the same call
// differently would let a client run a tool the guard never read; that is
// refused. A delta carrying a new id is a new call and starts a new record —
// except on native SSE, where a call's index is one slot, not a free id: a
// different non-empty id claiming an index that already has one is the index
// being reused to carry a different call's name without tripping the plain
// rename check below, and is refused the same way.
func (g *streamGuard) checkToolNames(ev *streamEvent) {
	for _, tc := range ev.toolCalls {
		if tc.Name == "" {
			continue
		}
		key := chatToolKey{choice: ev.choice, index: tc.Index}
		prev, ok := g.toolNames[key]
		switch {
		case ok && g.nativeSSETools && tc.ID != "" && prev.id != "" && tc.ID != prev.id:
			g.toolRenamed = true
		case !ok, tc.ID != "" && tc.ID != prev.id:
			if g.toolNames == nil {
				g.toolNames = map[chatToolKey]chatToolName{}
			}
			g.toolNames[key] = chatToolName{id: tc.ID, name: tc.Name}
		case tc.Name != prev.name:
			g.toolRenamed = true
		}
	}
}

// chatToolCapped resolves a block that has to be inspected while a tool call
// is still open, which only the nativeToolHold cap or the held-bytes ceiling
// causes: the guard would read part of the arguments and the rest would be
// released unread. It covers chat completions and native SSE tool calls. It
// reports whether the stream must stop, which is what fail_closed does.
// Anything else releases the call and records it.
func (g *streamGuard) chatToolCapped() bool {
	if (!g.chatTools() && !g.nativeSSETools) || !g.toolOpen || g.terminal || g.exhausted || g.srcErr != nil {
		return false
	}
	cause := "size"
	if g.now().Sub(g.toolSince) >= g.cfg.nativeToolHold {
		cause = "time"
	}
	if g.cfg.onError == streamFailClosed {
		if g.logger != nil {
			g.logger.Warn("tool call outgrew the hold; refusing it",
				slog.String("cause", cause),
				slog.String("format", string(g.source)))
		}
		return true
	}
	g.degrade(degradeToolInputUninspected)
	if !g.toolUninspectedLogged && g.logger != nil {
		g.toolUninspectedLogged = true
		g.logger.Warn("tool call released without inspecting its input",
			slog.String("cause", cause),
			slog.String("format", string(g.source)))
	}
	return false
}

// remaskChatToolCalls writes complete masked arguments into the first held
// delta of each changed call and clears its later deltas. It refuses a call
// whose arguments were windowed for the inspection, since the verdict covers
// only their tail, and a call with a delta the client already received. Nothing
// is changed until every touched event has been re-encoded.
func (g *streamGuard) remaskChatToolCalls(transformed []adapter.CanonicalToolCall) bool {
	if !g.chatTools() {
		return g.cannotMask(adapter.MaskCauseToolInput)
	}
	current := g.tools.calls()
	inspected := g.inspectedTools
	if len(transformed) != len(inspected) || len(current) != len(inspected) {
		return g.cannotMask(adapter.MaskCauseToolInput)
	}
	replacements := make(map[int]string)
	for i := range inspected {
		if transformed[i].Arguments == inspected[i].Arguments {
			continue
		}
		if inspected[i].Arguments != current[i].Arguments {
			return g.cannotMask(adapter.MaskCauseNoWindow)
		}
		replacements[g.tools.order[i]] = transformed[i].Arguments
	}
	if len(replacements) == 0 {
		return true
	}
	for _, ev := range g.produced[:g.releasedIdx] {
		for _, tc := range ev.toolCalls {
			if _, ok := replacements[tc.Index]; ok {
				return g.cannotMask(adapter.MaskCauseReleasedInput)
			}
		}
	}

	type eventRewrite struct {
		ev     *streamEvent
		deltas []adapter.StreamToolCallDelta
		lines  [][]byte
	}
	var rewrites []eventRewrite
	carried := make(map[int]bool, len(replacements))
	for _, ev := range g.produced[g.releasedIdx:] {
		deltas := slices.Clone(ev.toolCalls)
		touched := false
		for j := range deltas {
			replacement, ok := replacements[deltas[j].Index]
			if !ok {
				continue
			}
			touched = true
			if carried[deltas[j].Index] {
				deltas[j].ArgumentsDelta = ""
				continue
			}
			deltas[j].ArgumentsDelta = replacement
			carried[deltas[j].Index] = true
		}
		if !touched {
			continue
		}
		lines, ok := rewriteChatToolCallArguments(ev.lines, deltas, replacements)
		if !ok {
			return g.cannotMask(adapter.MaskCauseToolFrames)
		}
		rewrites = append(rewrites, eventRewrite{ev: ev, deltas: deltas, lines: lines})
	}
	if len(carried) != len(replacements) {
		return g.cannotMask(adapter.MaskCauseReleasedInput)
	}
	for _, r := range rewrites {
		r.ev.toolCalls, r.ev.lines = r.deltas, r.lines
	}
	g.tools = toolCallDigest{}
	for _, ev := range g.produced {
		g.tools.merge(ev.toolCalls)
	}
	g.inspectedTools = nil
	return true
}

// rewriteChatToolCallArguments rewrites the argument fragments of one
// chat-completions SSE event to the values in deltas. Like the segmenter it
// reads the first data: line and choices[0] only, and every tool call there
// must line up with deltas, so a fragment the rewrite did not reach is refused
// rather than released. Unmodelled fields are kept as raw JSON.
func rewriteChatToolCallArguments(
	lines [][]byte,
	deltas []adapter.StreamToolCallDelta,
	replacements map[int]string,
) ([][]byte, bool) {
	at := -1
	var payload []byte
	for i, line := range lines {
		if p, ok := dataPayload(line); ok {
			at, payload = i, p
			break
		}
	}
	if at < 0 {
		return nil, false
	}
	var top, choice, delta map[string]json.RawMessage
	var choices, calls []json.RawMessage
	if !decodeJSONObject(payload, &top) ||
		!decodeJSONArray(top["choices"], &choices) || len(choices) == 0 ||
		!decodeJSONObject(choices[0], &choice) ||
		!decodeJSONObject(choice["delta"], &delta) ||
		!decodeJSONArray(delta["tool_calls"], &calls) ||
		len(calls) != len(deltas) {
		return nil, false
	}
	for j, d := range deltas {
		if _, ok := replacements[d.Index]; !ok {
			continue
		}
		var call, fn map[string]json.RawMessage
		var index int
		if !decodeJSONObject(calls[j], &call) || json.Unmarshal(call["index"], &index) != nil || index != d.Index {
			return nil, false
		}
		kind, field := "function", "arguments"
		var typ string
		_ = json.Unmarshal(call["type"], &typ)
		if raw, ok := call["custom"]; typ == "custom" || (ok && !isJSONNull(raw)) {
			kind, field = "custom", "input"
		}
		if !decodeJSONObject(call[kind], &fn) {
			return nil, false
		}
		var ok bool
		if fn[field], ok = encodeJSON(d.ArgumentsDelta); !ok {
			return nil, false
		}
		if call[kind], ok = encodeJSON(fn); !ok {
			return nil, false
		}
		if calls[j], ok = encodeJSON(call); !ok {
			return nil, false
		}
	}
	var ok bool
	if delta["tool_calls"], ok = encodeJSON(calls); !ok {
		return nil, false
	}
	if choice["delta"], ok = encodeJSON(delta); !ok {
		return nil, false
	}
	if choices[0], ok = encodeJSON(choice); !ok {
		return nil, false
	}
	if top["choices"], ok = encodeJSON(choices); !ok {
		return nil, false
	}
	encoded, ok := encodeJSON(top)
	if !ok {
		return nil, false
	}
	out := slices.Clone(lines)
	out[at] = append([]byte("data: "), encoded...)
	return out, true
}

func decodeJSONObject(raw json.RawMessage, into *map[string]json.RawMessage) bool {
	return len(raw) > 0 && json.Unmarshal(raw, into) == nil && *into != nil
}

func decodeJSONArray(raw json.RawMessage, into *[]json.RawMessage) bool {
	return len(raw) > 0 && json.Unmarshal(raw, into) == nil && *into != nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func encodeJSON(v any) (json.RawMessage, bool) {
	raw, err := json.Marshal(v)
	return raw, err == nil
}
