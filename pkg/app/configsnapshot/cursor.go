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

package configsnapshot

import (
	"maps"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	defaultGapExpiry = 30 * time.Second
	defaultLateBound = 1024
)

// dirtySet is what the markers observed in one cycle changed. A full set asks
// for a full compile, with the reason it was needed.
type dirtySet struct {
	full       bool
	fullReason compileReason
	catalog    bool
	gateways   map[ids.GatewayID]struct{}
	markers    int
}

func (s *dirtySet) forceFull(reason compileReason) {
	if !s.full {
		s.full, s.fullReason = true, reason
	}
}

func (s *dirtySet) add(m configsyncport.Marker) {
	s.markers++
	switch m.Kind {
	case configsyncport.MarkerGateway:
		if s.gateways == nil {
			s.gateways = make(map[ids.GatewayID]struct{})
		}
		s.gateways[m.GatewayID] = struct{}{}
	case configsyncport.MarkerCatalog:
		s.catalog = true
	default:
		s.forceFull(compileReasonUnnamedMarker)
	}
}

// cursorState is one replica's read position in the outbox. Seqs at or below
// lowWater are settled; seen holds the seqs above it already observed, gaps
// the missing seqs above it still awaited, and late the gaps that expired,
// which are re-read every cycle because seq is assigned at INSERT, not COMMIT.
type cursorState struct {
	initialised bool
	lowWater    int64
	seen        map[int64]struct{}
	gaps        map[int64]time.Time
	late        map[int64]time.Time
}

func (s cursorState) clone() cursorState {
	return cursorState{
		initialised: s.initialised,
		lowWater:    s.lowWater,
		seen:        cloneOrEmpty(s.seen),
		gaps:        cloneOrEmpty(s.gaps),
		late:        cloneOrEmpty(s.late),
	}
}

func cloneOrEmpty[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return make(map[K]V)
	}
	return maps.Clone(m)
}

// outboxCursor tracks what one replica has read from the shared outbox. It
// never deletes markers: Observe computes the next position without changing
// the current one, and Commit adopts it only once the cycle has published, so
// a failed cycle re-reads the same markers. Only the dispatch loop uses it.
type outboxCursor struct {
	gapExpiry     time.Duration
	lateRetention time.Duration
	lateBound     int
	state         cursorState
}

func newOutboxCursor(gapExpiry, lateRetention time.Duration, lateBound int) *outboxCursor {
	if gapExpiry <= 0 {
		gapExpiry = defaultGapExpiry
	}
	if lateRetention <= 0 {
		lateRetention = defaultRetention
	}
	if lateBound <= 0 {
		lateBound = defaultLateBound
	}
	return &outboxCursor{gapExpiry: gapExpiry, lateRetention: lateRetention, lateBound: lateBound}
}

func (c *outboxCursor) readFrom() int64 {
	return c.state.lowWater
}

func (c *outboxCursor) lateSeqs() []int64 {
	out := make([]int64, 0, len(c.state.late))
	for seq := range c.state.late {
		out = append(out, seq)
	}
	return out
}

// observe folds the markers read this cycle (those above readFrom, and the
// late ones found again) into the next cursor state and the dirty set they
// imply. bounds are the lowest and highest seq left in the outbox, zero when it
// is empty.
func (c *outboxCursor) observe(markers, lateFound []configsyncport.Marker, bounds configsyncport.OutboxBounds, now time.Time) (cursorState, dirtySet) {
	minSeq := bounds.Min
	if c.state.initialised && bounds.Max > 0 && bounds.Max < c.state.lowWater {
		// Every seq left is below what this replica already settled: the
		// sequence restarted (a restored or recreated table), so markers above
		// the cursor would never be read again.
		var dirty dirtySet
		dirty.forceFull(compileReasonCursorReset)
		return cursorState{initialised: true, lowWater: minSeq - 1, seen: map[int64]struct{}{}, gaps: map[int64]time.Time{}, late: map[int64]time.Time{}}, dirty
	}
	next := c.state.clone()
	var dirty dirtySet

	if !next.initialised {
		// Seqs below the oldest row at the first read are not awaited: the
		// compile this cycle feeds is full, and a write still in flight at
		// start-up is covered by the backstop.
		if minSeq > 0 {
			next.lowWater = minSeq - 1
		}
		next.initialised = minSeq > 0
	} else if c.pruned(minSeq) {
		dirty.forceFull(compileReasonCursorReset)
		next.lowWater = minSeq - 1
		for seq := range next.seen {
			if seq <= next.lowWater {
				delete(next.seen, seq)
			}
		}
		for seq := range next.gaps {
			if seq <= next.lowWater {
				delete(next.gaps, seq)
			}
		}
	}

	highest := next.lowWater
	for _, batch := range [][]configsyncport.Marker{lateFound, markers} {
		for _, m := range batch {
			delete(next.late, m.Seq)
			if m.Seq <= next.lowWater {
				if _, wasLate := c.state.late[m.Seq]; !wasLate {
					continue
				}
			} else {
				if _, ok := next.seen[m.Seq]; ok {
					continue
				}
				next.seen[m.Seq] = struct{}{}
				delete(next.gaps, m.Seq)
				highest = max(highest, m.Seq)
			}
			dirty.add(m)
		}
	}
	for seq := range next.seen {
		highest = max(highest, seq)
	}
	for seq := next.lowWater + 1; seq < highest; seq++ {
		if _, ok := next.seen[seq]; ok {
			continue
		}
		if _, ok := next.late[seq]; ok {
			continue
		}
		if _, ok := next.gaps[seq]; !ok {
			next.gaps[seq] = now
		}
	}

	for seq, since := range next.gaps {
		if now.Sub(since) >= c.gapExpiry {
			delete(next.gaps, seq)
			next.late[seq] = now
		}
	}
	for seq, since := range next.late {
		if now.Sub(since) >= c.lateRetention {
			delete(next.late, seq)
		}
	}
	if len(next.late) > c.lateBound {
		dirty.forceFull(compileReasonCursorReset)
		next.late = make(map[int64]time.Time)
	}

	next.lowWater = highest
	for seq := range next.gaps {
		next.lowWater = min(next.lowWater, seq-1)
	}
	for seq := range next.seen {
		if seq <= next.lowWater {
			delete(next.seen, seq)
		}
	}
	return next, dirty
}

// pruned reports whether rows this replica never read were removed: the oldest
// row left is past the next seq it expects, and the seqs in between are
// neither gaps it already knows to be missing nor markers it already read.
func (c *outboxCursor) pruned(minSeq int64) bool {
	if minSeq == 0 || minSeq <= c.state.lowWater+1 {
		return false
	}
	missing := minSeq - c.state.lowWater - 1
	if missing > int64(len(c.state.gaps)+len(c.state.late)+len(c.state.seen)) {
		return true
	}
	for seq := c.state.lowWater + 1; seq < minSeq; seq++ {
		_, gap := c.state.gaps[seq]
		_, late := c.state.late[seq]
		_, seen := c.state.seen[seq]
		if !gap && !late && !seen {
			return true
		}
	}
	return false
}

func (c *outboxCursor) commit(next cursorState) {
	c.state = next
}
