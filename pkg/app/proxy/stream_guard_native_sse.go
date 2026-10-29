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
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// sseOpenCall is one native SSE tool call the guard is still holding. id is
// the call id the start event named, when it named one.
type sseOpenCall struct {
	id string
}

// trackNativeSSETool holds every native SSE tool call that is still open and
// checks the name and arguments each event claims for it. The block stays
// open until every one of them has closed, and the call is inspected once,
// through the segment's tool calls. Bedrock frames keep their own tracker:
// they are masked in place, and this path does not.
func (g *streamGuard) trackNativeSSETool(ev *streamEvent) {
	g.checkToolNames(ev)
	g.reconcileNativeSSEArgs(ev)
	if ev.unit == unitTerminal {
		g.sseOpen = nil
		g.toolOpen = false
		return
	}
	switch ev.tool {
	case toolNone:
	case toolStart, toolDelta:
		g.openNativeSSETool(ev)
	case toolStop:
		g.closeNativeSSETool(ev)
	default:
		// toolPhase has no other variant. A new one must say here whether it
		// opens or closes a call before it can change the hold.
		var unknown toolPhase = ev.tool
		_ = unknown
	}
}

func (g *streamGuard) openNativeSSETool(ev *streamEvent) {
	if g.sseOpen == nil {
		g.sseOpen = map[int]sseOpenCall{}
	}
	if _, ok := g.sseOpen[ev.toolIndex]; !ok {
		g.sseOpen[ev.toolIndex] = sseOpenCall{id: sseEventCallID(ev)}
	}
	if !g.toolOpen {
		g.toolSince = g.now()
	}
	g.toolOpen = true
	g.toolOpenIdx = ev.toolIndex
}

// closeNativeSSETool closes the call ev names. A stop that names no index, or
// an index that is not open, does not close a call that is open under another
// index. A stop whose call id disagrees with the id the call opened with does
// not close it either.
func (g *streamGuard) closeNativeSSETool(ev *streamEvent) {
	idx := ev.toolIndex
	if idx < 0 {
		idx = -1
	}
	open, ok := g.sseOpen[idx]
	if !ok {
		return
	}
	if id := sseEventCallID(ev); id != "" && open.id != "" && id != open.id {
		return
	}
	delete(g.sseOpen, idx)
	g.toolOpen = len(g.sseOpen) > 0
}

func sseEventCallID(ev *streamEvent) string {
	for _, tc := range ev.toolCalls {
		if tc.ID != "" {
			return tc.ID
		}
	}
	return ""
}

// reconcileNativeSSEArgs folds a boundary event's full arguments into the
// digest without appending them onto the deltas, and records a disagreement.
// A content_block_start or output_item.added that already carries a complete
// input is sealed: a later delta conflicts with it. An incomplete input is a
// prefix, and a delta that stops the concatenation being one JSON value is
// an invalid append.
func (g *streamGuard) reconcileNativeSSEArgs(ev *streamEvent) {
	for _, tc := range ev.toolCalls {
		if tc.ArgumentsDelta != "" && ev.tool != toolStart {
			if _, sealed := g.sseSealed[tc.Index]; sealed {
				g.toolArgsMismatch = true
			}
			if _, prefix := g.ssePrefix[tc.Index]; prefix && !jsonArgumentPrefix(g.toolArguments(tc.Index)) {
				g.toolArgsMismatch = true
			}
		}
		if ev.tool == toolStart && tc.ArgumentsDelta != "" {
			switch {
			case json.Valid([]byte(tc.ArgumentsDelta)):
				g.sealNativeSSEArgs(tc.Index)
			case jsonArgumentPrefix(tc.ArgumentsDelta):
				g.markNativeSSEPrefix(tc.Index)
			default:
				g.toolArgsMismatch = true
			}
		}
		if !tc.HasArgumentsSnapshot {
			continue
		}
		current := g.toolArguments(tc.Index)
		switch {
		case current == tc.ArgumentsSnapshot:
			g.sealNativeSSEArgs(tc.Index)
		case current == "":
			g.adoptToolArguments(tc.Index, tc.ArgumentsSnapshot)
			g.sealNativeSSEArgs(tc.Index)
		default:
			g.toolArgsMismatch = true
		}
	}
}

func (g *streamGuard) sealNativeSSEArgs(idx int) {
	if g.sseSealed == nil {
		g.sseSealed = map[int]struct{}{}
	}
	g.sseSealed[idx] = struct{}{}
}

func (g *streamGuard) markNativeSSEPrefix(idx int) {
	if g.ssePrefix == nil {
		g.ssePrefix = map[int]struct{}{}
	}
	g.ssePrefix[idx] = struct{}{}
}

func (g *streamGuard) toolArguments(idx int) string {
	if call := g.tools.byIdx[idx]; call != nil {
		return call.Arguments
	}
	return ""
}

func (g *streamGuard) adoptToolArguments(idx int, snapshot string) {
	if g.tools.byIdx == nil {
		g.tools.byIdx = map[int]*adapter.CanonicalToolCall{}
	}
	call := g.tools.byIdx[idx]
	if call == nil {
		call = &adapter.CanonicalToolCall{}
		g.tools.byIdx[idx] = call
		g.tools.order = append(g.tools.order, idx)
	}
	call.Arguments = snapshot
}

// jsonArgumentPrefix reports whether s is empty, one JSON value, or the start
// of one JSON value. A second value appended after a complete one is not.
func jsonArgumentPrefix(s string) bool {
	if strings.TrimSpace(s) == "" {
		return true
	}
	dec := json.NewDecoder(strings.NewReader(s))
	var value any
	err := dec.Decode(&value)
	if err == nil {
		var extra any
		return errors.Is(dec.Decode(&extra), io.EOF)
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) && strings.Contains(err.Error(), "unexpected end") {
		return true
	}
	return false
}
