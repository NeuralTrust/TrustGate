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
		for idx := range g.sseOpen {
			g.checkNativeSSEPrefix(idx)
		}
		g.sseOpen = nil
		g.toolOpen = false
		return
	}
	switch ev.tool {
	case toolStart, toolDelta:
		g.openNativeSSETool(ev)
	case toolStop:
		g.closeNativeSSETool(ev)
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
	open, ok := g.sseOpen[ev.toolIndex]
	if !ok {
		return
	}
	if id := sseEventCallID(ev); id != "" && open.id != "" && id != open.id {
		return
	}
	g.checkNativeSSEPrefix(ev.toolIndex)
	delete(g.sseOpen, ev.toolIndex)
	g.toolOpen = len(g.sseOpen) > 0
}

// checkNativeSSEPrefix records an invalid append once the call is whole,
// rather than re-parsing the growing arguments on every delta.
func (g *streamGuard) checkNativeSSEPrefix(idx int) {
	if _, prefix := g.ssePrefix[idx]; prefix && !jsonArgumentPrefix(g.toolArguments(idx)) {
		g.toolArgsMismatch = true
	}
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
// an invalid append. A custom tool's input is freeform text, not JSON, so it
// is checked only against the snapshots its boundary events state.
func (g *streamGuard) reconcileNativeSSEArgs(ev *streamEvent) {
	for _, tc := range ev.toolCalls {
		if tc.ArgumentsDelta != "" && ev.tool != toolStart {
			if _, sealed := g.sseSealed[tc.Index]; sealed {
				g.toolArgsMismatch = true
			}
		}
		if ev.tool == toolStart && tc.ArgumentsDelta != "" && tc.Kind != adapter.ToolKindCustom {
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
		switch current := g.toolArguments(tc.Index); current {
		case tc.ArgumentsSnapshot:
			g.sealNativeSSEArgs(tc.Index)
		case "":
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
	return errors.Is(err, io.ErrUnexpectedEOF)
}
