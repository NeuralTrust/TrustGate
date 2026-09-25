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
	"unicode"
	"unicode/utf8"
)

const maxDiffEdits = 512

// textHunk replaces before[start:end] with insert.
type textHunk struct {
	start, end int
	insert     string
}

// diffText returns the edits that turn before into after, in order and
// without overlap. It trims the common prefix and suffix, diffs what is left
// by words, and trims each changed run again by characters, so a masked
// value comes out as its own hunk. It refuses when the texts differ in more
// than maxDiffEdits words.
func diffText(before, after string) ([]textHunk, bool) {
	if before == after {
		return nil, true
	}
	p, s := commonAffixes(before, after)
	a, b := before[p:len(before)-s], after[p:len(after)-s]
	if a == "" || b == "" {
		return []textHunk{{start: p, end: p + len(a), insert: b}}, true
	}
	ta, tb := tokenize(a), tokenize(b)
	matches, ok := myersMatches(a, ta, b, tb, maxDiffEdits)
	if !ok {
		return nil, false
	}
	var hunks []textHunk
	ai, bi := 0, 0
	gap := func(aEnd, bEnd int) {
		if aEnd == ai && bEnd == bi {
			return
		}
		ra, rb := tokenSpan(ta, a, ai, aEnd), tokenSpan(tb, b, bi, bEnd)
		off := tokenOffset(ta, a, ai)
		hp, hs := commonAffixes(ra, rb)
		if hp+hs == len(ra) && hp+hs == len(rb) {
			return
		}
		hunks = append(hunks, textHunk{start: p + off + hp, end: p + off + len(ra) - hs, insert: rb[hp : len(rb)-hs]})
	}
	for _, m := range matches {
		gap(m[0], m[1])
		ai, bi = m[0]+1, m[1]+1
	}
	gap(len(ta), len(tb))
	return hunks, true
}

type token struct{ start, end int }

func tokenSpan(ts []token, s string, from, to int) string {
	if from == to {
		return ""
	}
	return s[ts[from].start:ts[to-1].end]
}

func tokenOffset(ts []token, s string, i int) int {
	if i < len(ts) {
		return ts[i].start
	}
	return len(s)
}

func tokenize(s string) []token {
	var out []token
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		j := i + n
		if isWordRune(r) {
			for j < len(s) {
				r2, n2 := utf8.DecodeRuneInString(s[j:])
				if !isWordRune(r2) {
					break
				}
				j += n2
			}
		}
		out = append(out, token{i, j})
		i = j
	}
	return out
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// commonAffixes returns the lengths of the longest common prefix and suffix
// of a and b that end on rune boundaries and do not overlap.
func commonAffixes(a, b string) (int, int) {
	n := min(len(a), len(b))
	p := 0
	for p < n && a[p] == b[p] {
		p++
	}
	for p > 0 && (!runeBoundary(a, p) || !runeBoundary(b, p)) {
		p--
	}
	s := 0
	for s < n-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	for s > 0 && (!runeBoundary(a, len(a)-s) || !runeBoundary(b, len(b)-s)) {
		s--
	}
	return p, s
}

func runeBoundary(s string, i int) bool {
	return i >= len(s) || utf8.RuneStart(s[i])
}

// myersMatches returns the index pairs of a longest common subsequence of
// the tokens of a and b, found with Myers' O((N+M)D) algorithm, or false
// when more than maxD insertions and deletions are needed.
func myersMatches(a string, ta []token, b string, tb []token, maxD int) ([][2]int, bool) {
	n, m := len(ta), len(tb)
	eq := func(x, y int) bool { return a[ta[x].start:ta[x].end] == b[tb[y].start:tb[y].end] }
	maxD = min(maxD, n+m)
	off := maxD + 1
	v := make([]int, 2*maxD+3)
	var trace [][]int
	for d := 0; d <= maxD; d++ {
		trace = append(trace, append([]int(nil), v[off-d-1:off+d+2]...))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && eq(x, y) {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				return myersBacktrack(trace, n, m), true
			}
		}
	}
	return nil, false
}

func myersBacktrack(trace [][]int, n, m int) [][2]int {
	var matches [][2]int
	x, y := n, m
	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		at := func(k int) int { return v[k+d+1] }
		k := x - y
		prevK := k - 1
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			prevK = k + 1
		}
		prevX := at(prevK)
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			matches = append(matches, [2]int{x, y})
		}
		x, y = prevX, prevY
	}
	for i, j := 0, len(matches)-1; i < j; i, j = i+1, j-1 {
		matches[i], matches[j] = matches[j], matches[i]
	}
	return matches
}
