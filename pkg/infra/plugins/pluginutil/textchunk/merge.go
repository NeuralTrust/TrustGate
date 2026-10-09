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

package textchunk

import (
	"sort"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type hunk struct {
	start, end int
	insert     string
	chunk      int
}

// MergeMasks maps what each chunk's provider masked back onto original.
// masked[i] == chunks[i].Text means chunk i asked for nothing. Where two
// chunks cover the same bytes (the overlap) and ask for the same mask, it is
// applied once; where they differ, the union of the spans is replaced by the
// insert of the longer original span, so no byte any chunk masked is left in
// the result. ok is false when a chunk's mask cannot be read as a few
// replacements, or the replacements do not fit the original: a mask that
// cannot be applied must not be dropped.
func MergeMasks(original string, chunks []Chunk, masked []string) (string, bool) {
	if len(masked) != len(chunks) {
		return "", false
	}
	var hunks []hunk
	for i, c := range chunks {
		if masked[i] == c.Text {
			continue
		}
		hs, ok := adapter.DiffText(c.Text, masked[i])
		if !ok {
			return "", false
		}
		for _, h := range hs {
			hunks = append(hunks, hunk{start: c.Start + h.Start, end: c.Start + h.End, insert: h.Insert, chunk: i})
		}
	}
	if len(hunks) == 0 {
		return original, true
	}
	sort.SliceStable(hunks, func(a, b int) bool {
		if hunks[a].start != hunks[b].start {
			return hunks[a].start < hunks[b].start
		}
		if hunks[a].end != hunks[b].end {
			return hunks[a].end < hunks[b].end
		}
		return hunks[a].chunk < hunks[b].chunk
	})

	merged := make([]hunk, 0, len(hunks))
	cur := hunks[0]
	owner := cur
	for _, h := range hunks[1:] {
		if h.start == cur.start && h.end == cur.end && h.insert == cur.insert {
			continue
		}
		touches := h.start == cur.end && h.start < h.end && cur.start < cur.end
		if h.start < cur.end || touches {
			if h.end > cur.end {
				cur.end = h.end
			}
			if h.end-h.start > owner.end-owner.start {
				owner = h
			}
			cur.insert = owner.insert
			continue
		}
		merged = append(merged, cur)
		cur, owner = h, h
	}
	merged = append(merged, cur)

	var b strings.Builder
	prev := 0
	for _, h := range merged {
		if h.start < prev || h.start > h.end || h.end > len(original) {
			return "", false
		}
		b.WriteString(original[prev:h.start])
		b.WriteString(h.insert)
		prev = h.end
	}
	b.WriteString(original[prev:])
	return b.String(), true
}
