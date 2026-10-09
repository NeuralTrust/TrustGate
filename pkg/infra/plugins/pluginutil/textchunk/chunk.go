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

// Package textchunk splits text into overlapping chunks that a provider with a
// per-call size limit can screen one by one, runs them with bounded
// concurrency, and maps the masks each chunk asked for back onto the original.
package textchunk

import (
	"unicode"
	"unicode/utf8"
)

// Unit is what a Spec's Max and Overlap count.
type Unit int

const (
	// Bytes counts UTF-8 bytes. It is an upper bound on characters, code
	// points and UTF-16 units, so a provider that limits any of them is
	// within its limit.
	Bytes Unit = iota
	// UTF16 counts UTF-16 code units: a code point above U+FFFF counts 2.
	UTF16
)

// Spec says how to cut a text. Max is the hard cap of a chunk. Overlap is the
// least the end of a chunk is shared with the start of the next: every
// substring of at most Overlap units lies whole in at least one chunk.
type Spec struct {
	Max     int
	Overlap int
	Unit    Unit
}

// Chunk is text[Start:End], a substring of the original that shares its
// memory.
type Chunk struct {
	Start, End int
	Text       string
}

// of is the cost of the rune r that took size bytes of the text. An invalid
// byte is sent on as U+FFFD, which is 3 bytes, so it costs 3 and Bytes stays an
// upper bound for a provider that is sent the re-encoded text.
func (u Unit) of(r rune, size int) int {
	if u == UTF16 {
		if r >= 0x10000 {
			return 2
		}
		return 1
	}
	if r == utf8.RuneError && size == 1 {
		return len(string(utf8.RuneError))
	}
	return size
}

// Split returns the chunks of text. It never copies the text into runes: it
// walks it with utf8.DecodeRuneInString. A chunk ends at the last '\n', else
// the last Unicode space, in the final eighth of its window, else at the last
// rune boundary under Max. The next chunk starts Overlap units before that
// end, moved back to a rune start. Text of at most Max units is one chunk. It
// panics when Max <= Overlap or Max < 1, which is a programmer error.
func Split(text string, s Spec) []Chunk {
	checkSpec(s)
	if text == "" {
		return []Chunk{{}}
	}
	var out []Chunk
	for start, last := 0, false; !last; {
		var end, next int
		end, next, last = step(text, start, s)
		out = append(out, Chunk{Start: start, End: end, Text: text[start:end]})
		start = next
	}
	return out
}

// Count is len(Split(text, s)) without building the slice, so a caller can
// refuse an oversize input before allocating anything for it.
func Count(text string, s Spec) int {
	checkSpec(s)
	n := 0
	for start, last := 0, false; !last; n++ {
		_, start, last = step(text, start, s)
	}
	return n
}

func checkSpec(s Spec) {
	if s.Max < 1 || s.Overlap < 0 || s.Max <= s.Overlap {
		panic("textchunk: Max must be positive and greater than Overlap")
	}
}

// step cuts the chunk that starts at start and returns where it ends, where the
// next one starts, and whether this is the last.
func step(text string, start int, s Spec) (end, next int, last bool) {
	floor := s.Max - s.Max/8
	units, i := 0, start
	newline, space := -1, -1
	for i < len(text) {
		r, n := utf8.DecodeRuneInString(text[i:])
		u := s.Unit.of(r, n)
		if units+u > s.Max {
			break
		}
		units += u
		i += n
		if units >= floor {
			if r == '\n' {
				newline = i
			} else if unicode.IsSpace(r) {
				space = i
			}
		}
	}
	if i >= len(text) {
		return len(text), len(text), true
	}
	end = i
	switch {
	case newline >= 0:
		end = newline
	case space >= 0:
		end = space
	case end == start:
		_, n := utf8.DecodeRuneInString(text[start:])
		end = start + n
	}
	next = end
	for back := 0; next > start && back < s.Overlap; {
		r, n := utf8.DecodeLastRuneInString(text[:next])
		back += s.Unit.of(r, n)
		next -= n
	}
	if next <= start {
		_, n := utf8.DecodeRuneInString(text[start:])
		next = start + n
	}
	return end, next, false
}
