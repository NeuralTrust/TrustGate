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

// refusedChatTool reports a chat tool stream the guard will not release: a
// call whose name changed, more than one choice, or a choice index that could
// not be read. Each is a cut, whichever way on_error is set. The cap is a
// separate decision (chatToolCapped).
func (g *streamGuard) refusedChatTool() (string, bool) {
	switch {
	case g.toolRenamed:
		return streamToolRenamedMessage, true
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
// refused. A delta carrying a new id is a new call and starts a new record.
func (g *streamGuard) checkToolNames(ev *streamEvent) {
	for _, tc := range ev.toolCalls {
		if tc.Name == "" {
			continue
		}
		key := chatToolKey{choice: ev.choice, index: tc.Index}
		prev, ok := g.toolNames[key]
		switch {
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

// chatToolCapped resolves a block that has to be inspected while a chat tool
// call is still open, which only the nativeToolHold cap or the held-bytes
// ceiling causes: the guard would read part of the arguments and the rest
// would be released unread. It reports whether the stream must stop, which is
// what fail_closed does. Anything else releases the call and records it.
func (g *streamGuard) chatToolCapped() bool {
	if !g.chatTools() || !g.toolOpen || g.terminal || g.exhausted || g.srcErr != nil {
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
// delta for each changed call and clears its later deltas. Tool calls are held
// from their first delta through finish_reason, so no argument byte selected
// for replacement has reached the client.
func (g *streamGuard) remaskChatToolCalls(transformed []adapter.CanonicalToolCall) bool {
	if !g.chatTools() {
		return g.cannotMask(adapter.MaskCauseToolInput)
	}
	current := g.tools.calls()
	if len(current) != len(transformed) || len(current) != len(g.tools.order) {
		return g.cannotMask(adapter.MaskCauseToolInput)
	}
	replacements := make(map[int]string)
	for i := range current {
		if current[i].Arguments != transformed[i].Arguments {
			replacements[g.tools.order[i]] = transformed[i].Arguments
		}
	}
	if len(replacements) == 0 {
		return true
	}

	carried := make(map[int]bool, len(replacements))
	for i := g.releasedIdx; i < len(g.produced); i++ {
		ev := g.produced[i]
		for j := range ev.toolCalls {
			replacement, ok := replacements[ev.toolCalls[j].Index]
			if !ok {
				continue
			}
			if !carried[ev.toolCalls[j].Index] {
				ev.toolCalls[j].ArgumentsDelta = replacement
				carried[ev.toolCalls[j].Index] = true
			} else {
				ev.toolCalls[j].ArgumentsDelta = ""
			}
		}
	}
	if len(carried) != len(replacements) {
		return g.cannotMask(adapter.MaskCauseReleasedInput)
	}
	for i := g.releasedIdx; i < len(g.produced); i++ {
		ev := g.produced[i]
		lines, changed, ok := rewriteChatToolCallArguments(ev.lines, ev.toolCalls, replacements)
		if !ok {
			return g.cannotMask(adapter.MaskCauseToolFrames)
		}
		if changed {
			ev.lines = lines
		}
	}

	g.tools = toolCallDigest{}
	for _, ev := range g.produced {
		g.tools.merge(ev.toolCalls)
	}
	return true
}

// rewriteChatToolCallArguments replaces tool-call argument fragments in one
// chat-completions SSE event. It rebuilds only JSON containers around the
// changed fields; all unmodelled values remain json.RawMessage values.
func rewriteChatToolCallArguments(
	lines [][]byte,
	deltas []adapter.StreamToolCallDelta,
	replacements map[int]string,
) ([][]byte, bool, bool) {
	var rewritten [][]byte
	changed := false
	for _, line := range lines {
		const prefix = "data: "
		if !bytes.HasPrefix(line, []byte(prefix)) {
			rewritten = append(rewritten, line)
			continue
		}
		payload := line[len(prefix):]
		var top map[string]json.RawMessage
		if json.Unmarshal(payload, &top) != nil {
			return nil, false, false
		}
		var choices []json.RawMessage
		if raw, ok := top["choices"]; !ok || json.Unmarshal(raw, &choices) != nil {
			rewritten = append(rewritten, line)
			continue
		}
		deltaAt := 0
		lineChanged := false
		for ci, rawChoice := range choices {
			var choice map[string]json.RawMessage
			if json.Unmarshal(rawChoice, &choice) != nil {
				return nil, false, false
			}
			var delta map[string]json.RawMessage
			if raw, ok := choice["delta"]; !ok || json.Unmarshal(raw, &delta) != nil {
				continue
			}
			var calls []json.RawMessage
			if raw, ok := delta["tool_calls"]; !ok || json.Unmarshal(raw, &calls) != nil {
				continue
			}
			for callAt, rawCall := range calls {
				if deltaAt >= len(deltas) {
					return nil, false, false
				}
				d := deltas[deltaAt]
				deltaAt++
				if _, ok := replacements[d.Index]; !ok {
					continue
				}
				var call map[string]json.RawMessage
				if json.Unmarshal(rawCall, &call) != nil {
					return nil, false, false
				}
				kind, field := "function", "arguments"
				if _, ok := call["custom"]; ok {
					kind, field = "custom", "input"
				}
				var function map[string]json.RawMessage
				if raw, ok := call[kind]; !ok || json.Unmarshal(raw, &function) != nil {
					return nil, false, false
				}
				value, err := json.Marshal(d.ArgumentsDelta)
				if err != nil {
					return nil, false, false
				}
				function[field] = value
				value, err = json.Marshal(function)
				if err != nil {
					return nil, false, false
				}
				call[kind] = value
				value, err = json.Marshal(call)
				if err != nil {
					return nil, false, false
				}
				calls[callAt] = value
				lineChanged = true
			}
			if !lineChanged {
				continue
			}
			value, err := json.Marshal(calls)
			if err != nil {
				return nil, false, false
			}
			delta["tool_calls"] = value
			value, err = json.Marshal(delta)
			if err != nil {
				return nil, false, false
			}
			choice["delta"] = value
			value, err = json.Marshal(choice)
			if err != nil {
				return nil, false, false
			}
			choices[ci] = value
		}
		if deltaAt != len(deltas) {
			return nil, false, false
		}
		if !lineChanged {
			rewritten = append(rewritten, line)
			continue
		}
		value, err := json.Marshal(choices)
		if err != nil {
			return nil, false, false
		}
		top["choices"] = value
		value, err = json.Marshal(top)
		if err != nil {
			return nil, false, false
		}
		rewritten = append(rewritten, append([]byte(prefix), value...))
		changed = true
	}
	return rewritten, changed, true
}
