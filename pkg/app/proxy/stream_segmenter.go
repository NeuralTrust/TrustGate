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
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type streamUnit int

const (
	unitOpaque streamUnit = iota
	unitText
	unitUsage
	unitTerminal
)

// streamCodec is the narrow slice of the adapter registry the segmenter needs.
type streamCodec interface {
	DecodeStreamChunkFor(chunk []byte, target adapter.Format) (*adapter.CanonicalStreamChunk, error)
}

// responsesEventPrefix is how an OpenAI Responses SSE event names itself.
// OpenAIAdapter.DecodeStreamChunk sniffs this same prefix and hands the payload
// to the Responses decoder whatever format it was asked for
// (openai_adapter.go:56-64, :88-92), so a Responses event can reach
// classification under a plain "openai" label. The payload, not the label, is
// what decides how its finish reason must be read.
const responsesEventPrefix = "response."

// finishReasonToolCalls is the canonical finish reason for one completed tool
// call. On Responses it rides response.function_call_arguments.done, which
// fires once per function call well before the response ends.
const finishReasonToolCalls = "tool_calls"

// terminalPayloadTypes are the events that end a response in the dialects that
// name their ending. They are matched before the decode so that the end of a
// stream never depends on what the decoder happens to surface: message_stop,
// response.incomplete and response.failed decode to nothing at all, and error
// is how Anthropic and Responses end a stream abnormally — without it an
// aborted stream looks opaque and the guard never learns the stream is over.
// response.completed and cohere message-end do decode with a finish reason, but
// in their dialects a finish reason is not an ending (see
// dialectsWithExplicitEnd), so for those two the set is what makes them
// terminal rather than a redundant shortcut.
var terminalPayloadTypes = map[string]struct{}{
	"message_stop":        {},
	"message-end":         {},
	"response.completed":  {},
	"response.incomplete": {},
	"response.failed":     {},
	"error":               {},
}

// dialectsWithExplicitEnd are the wire formats that end a response with a named
// event. There a finish reason describes content, not the ending: Responses
// emits response.function_call_arguments.done — which decodes to FinishReason
// "tool_calls" (openai_responses_adapter.go:338-341) — once per function call
// before response.completed, and Anthropic puts the stop reason on
// message_delta, two events before message_stop. Classifying those as terminal
// would stamp a mid-stream segment final and stop every guard call after the
// first tool call. Every other dialect — the chat-completions family,
// Gemini/Vertex, Bedrock, Mistral — has no end event, so there the finish
// reason is the only ending there is.
var dialectsWithExplicitEnd = map[adapter.Format]struct{}{
	adapter.FormatAnthropic:       {},
	adapter.FormatCohere:          {},
	adapter.FormatOpenAIResponses: {},
}

// endsOnFinishReason reports whether a finish reason on this event is the end
// of the response rather than a property of what the event carries.
func endsOnFinishReason(format adapter.Format, payloadType string) bool {
	if strings.HasPrefix(payloadType, responsesEventPrefix) {
		return false
	}
	_, explicit := dialectsWithExplicitEnd[format]
	return !explicit
}

// streamEvent is one whole SSE event: its original lines in arrival order, plus
// what the event contributes to the block being filled. Anthropic, Cohere and
// Responses frame an event across several lines, so the event, not the line, is
// the unit that can be held and released without corrupting the wire.
type streamEvent struct {
	lines     [][]byte
	unit      streamUnit
	text      string
	reasoning string
	toolCalls []adapter.StreamToolCallDelta
}

// chars counts only what a guard call would actually read, which is why a tool
// call contributes its argument bytes and not its id or name.
func (e *streamEvent) chars() int {
	n := len(e.text) + len(e.reasoning)
	for _, tc := range e.toolCalls {
		n += len(tc.ArgumentsDelta)
	}
	return n
}

// segmenter assembles raw SSE lines into whole events and classifies what each
// one contributes. It is pure: no I/O, no plugin calls, no timers. It never
// re-encodes: an event carries the bytes it arrived as, because passthrough is
// byte-exact by contract and a re-encode would reorder usage, provider
// extensions and comments on the wire.
//
// Ownership: a line fed in is handed over, not copied, and comes back out in
// streamEvent.lines unchanged. The caller must feed lines it will not mutate or
// reuse afterwards, and must not mutate the lines it gets back. Every producer
// in the chain allocates per line today (providers/stream.go:62, the
// cross-format path, stream_toolcall_coalesce.go:71-73); a future one that
// reuses a scratch buffer would silently corrupt held blocks, and no test can
// catch it from the outside.
type segmenter struct {
	codec  streamCodec
	format adapter.Format
	buf    [][]byte
	anchor cutAnchor
}

// newSegmenter builds a segmenter for the source format. After adaptStream the
// lines are already in the caller's dialect, so source is what decodes them.
func newSegmenter(codec streamCodec, source adapter.Format) *segmenter {
	return &segmenter{codec: codec, format: source}
}

// feed accumulates one raw SSE line and returns a whole event once the event is
// complete, or nil while it is still open. A classification failure comes back
// alongside the event, never instead of it: the caller must still be able to
// release the original lines byte for byte. The line is handed over under the
// ownership contract on segmenter.
func (s *segmenter) feed(line []byte) (*streamEvent, error) {
	standalone := len(s.buf) == 0 && isSSEComment(line)
	s.buf = append(s.buf, line)
	if !standalone && len(bytes.TrimSpace(line)) != 0 {
		return nil, nil
	}
	return s.flush()
}

// flush exists for the end of the stream and for providers that omit the last
// separator.
func (s *segmenter) flush() (*streamEvent, error) {
	if len(s.buf) == 0 {
		return nil, nil
	}
	ev := &streamEvent{lines: s.buf}
	s.buf = nil
	return ev, s.classify(ev)
}

func (s *segmenter) classify(ev *streamEvent) error {
	var payload []byte
	for _, line := range ev.lines {
		if isSSEDone(line) {
			ev.unit = unitTerminal
			return nil
		}
		if p, ok := dataPayload(line); ok && payload == nil {
			payload = p
		}
	}
	// Only the first data: line of an event is accounted for. No registry
	// adapter can emit a multi-data: event, so nothing is lost today — and the
	// failure mode if one ever did is not the obvious one: the extra lines are
	// still released byte for byte, they are simply never classified. That is
	// text reaching the client without ever reaching the guard, an evasion
	// vector, not a dropped line.
	if payload == nil {
		return nil
	}
	eventType := ssePayloadType(payload)
	if isTerminalPayload(eventType) {
		ev.unit = unitTerminal
		return nil
	}
	chunk, err := s.codec.DecodeStreamChunkFor(payload, s.format)
	if err != nil {
		return fmt.Errorf("segmenting %s stream chunk: %w", s.format, err)
	}
	s.anchor.observe(chunk)
	if chunk == nil {
		return nil
	}
	ev.text, ev.reasoning, ev.toolCalls = chunk.Delta, chunk.ReasoningDelta, chunk.ToolCallDeltas
	switch {
	case chunk.FinishReason != "" && endsOnFinishReason(s.format, eventType):
		ev.unit = unitTerminal
	case ev.text != "" || ev.reasoning != "" || len(ev.toolCalls) > 0:
		ev.unit = unitText
	case chunk.Role != "":
		ev.unit = unitOpaque
	case chunk.Usage != nil:
		ev.unit = unitUsage
	case chunk.FinishReason == finishReasonToolCalls:
		// response.function_call_arguments.done: the close of one tool call, a
		// tool-call unit. Its arguments already rode the delta events, so it
		// adds no chars, but it must not be opaque either — opaque events are
		// releasable ahead of the block they sit in.
		ev.unit = unitText
	}
	return nil
}

// ssePayloadType reads the "type" discriminator Anthropic, Cohere and Responses
// put on every event. The chat-completions family, Gemini and Bedrock have no
// such field and yield "".
func ssePayloadType(payload []byte) string {
	var probe struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(payload, &probe) != nil {
		return ""
	}
	return probe.Type
}

func isTerminalPayload(payloadType string) bool {
	_, ok := terminalPayloadTypes[payloadType]
	return ok
}

func isSSEComment(line []byte) bool {
	return len(line) > 0 && line[0] == ':'
}

// blockClock is the segmenter's view of wall time and of the guard call in
// flight. It is injected so the block loop that owns those calls drives block
// closing, and so the segmenter keeps no timer of its own.
type blockClock interface {
	Now() time.Time
	GuardIdle() bool
}

// blockGate decides when the block being filled closes: on the terminal event,
// or once the previous guard call has returned and the block carries at least
// minChars, or once maxHold has elapsed since the block opened.
type blockGate struct {
	clock    blockClock
	minChars int
	maxHold  time.Duration
	chars    int
	openedAt time.Time
	open     bool
}

// minBlockMaxHold floors the ceiling. A maxHold of zero makes
// Now().Sub(openedAt) >= maxHold true on the very first event, so every event
// would close its own block and the guard-call multiplier of design §9 would
// grow with the event count instead of the byte count. Configuration already
// rejects anything below 50ms (§4.5); this is the same floor for a gate built
// straight from code.
const minBlockMaxHold = 50 * time.Millisecond

func newBlockGate(clock blockClock, minChars int, maxHold time.Duration) *blockGate {
	if maxHold < minBlockMaxHold {
		maxHold = minBlockMaxHold
	}
	return &blockGate{clock: clock, minChars: minChars, maxHold: maxHold}
}

func (g *blockGate) admit(ev *streamEvent) {
	if !g.open {
		g.open = true
		g.openedAt = g.clock.Now()
	}
	g.chars += ev.chars()
}

// shouldClose reports whether the block closes on ev, which must already have
// been admitted.
func (g *blockGate) shouldClose(ev *streamEvent) bool {
	if ev.unit == unitTerminal {
		return true
	}
	if !g.open {
		return false
	}
	if g.clock.Now().Sub(g.openedAt) >= g.maxHold {
		return true
	}
	return g.clock.GuardIdle() && g.chars >= g.minChars
}

// reset must run only once the closed block has been handed to the guard.
func (g *blockGate) reset() {
	g.open = false
	g.chars = 0
}
