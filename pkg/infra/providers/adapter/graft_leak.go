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

import "strings"

const maxLinearPieces = 16

// notePieces records the text each hunk removes from before, line by line
// and without surrounding blanks, so a copy of it that a block of the grafted
// body still carries can be found even when the removal spanned two blocks.
func (g *grafter) notePieces(before string, hunks []textHunk) {
	for _, h := range hunks {
		for _, line := range strings.Split(before[h.start:h.end], "\n") {
			piece := strings.TrimSpace(line)
			if piece == "" || (!g.opts.Redaction && len(piece) < minLeakPiece) {
				continue
			}
			if g.pieces == nil {
				g.pieces = map[string]struct{}{}
			}
			g.pieces[piece] = struct{}{}
		}
	}
}

// leaks reports whether a removed piece appears in a string of out that the
// full re-encode does not carry as well: a copy the canonical request does
// not model (a thinking block, a document, metadata) that the edit never
// reached. Strings are compared decoded, so escapes cannot hide a copy.
func (g *grafter) leaks(out []byte) bool {
	if len(g.pieces) == 0 {
		return false
	}
	carried := map[string]int{}
	if forEachString(g.encoded, func(s string) bool { carried[s]++; return true }) != nil {
		return true
	}
	contains := pieceMatcher(g.pieces)
	leaked := false
	err := forEachString(out, func(s string) bool {
		if carried[s] > 0 {
			carried[s]--
			return true
		}
		leaked = contains(s)
		return !leaked
	})
	return err != nil || leaked
}

func pieceMatcher(pieces map[string]struct{}) func(string) bool {
	if len(pieces) <= maxLinearPieces {
		return func(s string) bool {
			for p := range pieces {
				if strings.Contains(s, p) {
					return true
				}
			}
			return false
		}
	}
	pairs := make([]string, 0, 2*len(pieces))
	for p := range pieces {
		pairs = append(pairs, p, "")
	}
	r := strings.NewReplacer(pairs...)
	return func(s string) bool { return r.Replace(s) != s }
}
