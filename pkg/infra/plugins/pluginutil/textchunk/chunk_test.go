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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unitsOf(s string, u Unit) int {
	n := 0
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		n += u.of(r, w)
		i += w
	}
	return n
}

func assertInvariants(t *testing.T, text string, s Spec) []Chunk {
	t.Helper()
	chunks := Split(text, s)
	require.NotEmpty(t, chunks)
	assert.Equal(t, len(chunks), Count(text, s))
	assert.Equal(t, 0, chunks[0].Start)
	assert.Equal(t, len(text), chunks[len(chunks)-1].End)
	for i, c := range chunks {
		assert.Equal(t, text[c.Start:c.End], c.Text)
		assert.True(t, utf8.ValidString(c.Text) == utf8.ValidString(text) || !utf8.ValidString(text))
		assert.LessOrEqual(t, unitsOf(c.Text, s.Unit), s.Max, "chunk %d", i)
		if i > 0 {
			assert.Greater(t, c.Start, chunks[i-1].Start, "starts advance")
			assert.LessOrEqual(t, c.Start, chunks[i-1].End, "chunks leave no gap")
		}
	}
	return chunks
}

func assertOverlapGuarantee(t *testing.T, text string, s Spec, chunks []Chunk) {
	t.Helper()
	for a := 0; a < len(text); {
		_, n := utf8.DecodeRuneInString(text[a:])
		end, units := a, 0
		for end < len(text) {
			r, w := utf8.DecodeRuneInString(text[end:])
			u := s.Unit.of(r, w)
			if units+u > s.Overlap {
				break
			}
			units += u
			end += w
		}
		if end > a {
			held := false
			for _, c := range chunks {
				if c.Start <= a && end <= c.End {
					held = true
					break
				}
			}
			require.True(t, held, "the %d units at byte %d lie whole in no chunk", units, a)
		}
		a += n
	}
}

func TestSplitFitsAndCoversEveryUnit(t *testing.T) {
	t.Parallel()
	four := strings.Repeat("\U0001F600", 5000)
	cases := []struct {
		name string
		text string
		spec Spec
	}{
		{"four-byte runes at the byte cap", four, Spec{Max: 1000, Overlap: 100, Unit: Bytes}},
		{"astral runes count two UTF-16 units", four, Spec{Max: 1000, Overlap: 100, Unit: UTF16}},
		{"CRLF text", strings.Repeat("line of text\r\n", 3000), Spec{Max: 500, Overlap: 50, Unit: Bytes}},
		{"no whitespace at all", strings.Repeat("a", 100*1024), Spec{Max: 8192, Overlap: 512, Unit: Bytes}},
		{"mixed scripts", strings.Repeat("héllo wörld 日本語 ", 2000), Spec{Max: 700, Overlap: 70, Unit: Bytes}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chunks := assertInvariants(t, tc.text, tc.spec)
			assertOverlapGuarantee(t, tc.text, tc.spec, chunks)
		})
	}
}

func TestSplitAstralCharactersCountTwoUTF16Units(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("\U0001F600", 10)
	assert.Len(t, Split(text, Spec{Max: 20, Overlap: 2, Unit: UTF16}), 1)
	chunks := Split(text, Spec{Max: 19, Overlap: 2, Unit: UTF16})
	require.Greater(t, len(chunks), 1)
	for _, c := range chunks {
		assert.LessOrEqual(t, unitsOf(c.Text, UTF16), 19)
	}
	assert.Len(t, Split(text, Spec{Max: 40, Overlap: 2, Unit: Bytes}), 1)
	assert.Greater(t, len(Split(text, Spec{Max: 39, Overlap: 2, Unit: Bytes})), 1)
}

func TestSplitBreaksOnANewlineThenAnySpaceInTheLastEighth(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("a", 90) + "\n" + strings.Repeat("b", 20) + " " + strings.Repeat("c", 200)
	chunks := Split(text, Spec{Max: 100, Overlap: 5, Unit: Bytes})
	assert.Equal(t, 91, chunks[0].End, "the newline in the last eighth wins")

	text = strings.Repeat("a", 95) + " " + strings.Repeat("c", 200)
	chunks = Split(text, Spec{Max: 100, Overlap: 5, Unit: Bytes})
	assert.Equal(t, 96, chunks[0].End, "a space is the fallback")

	text = strings.Repeat("a", 10) + " " + strings.Repeat("c", 200)
	chunks = Split(text, Spec{Max: 100, Overlap: 5, Unit: Bytes})
	assert.Equal(t, 100, chunks[0].End, "a space outside the last eighth is not used")
}

func TestSplitTextWithinMaxIsOneChunk(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []Chunk{{Start: 0, End: 5, Text: "hello"}}, Split("hello", Spec{Max: 5, Overlap: 1, Unit: Bytes}))
	assert.Equal(t, []Chunk{{}}, Split("", Spec{Max: 5, Overlap: 1, Unit: Bytes}))
	assert.Equal(t, 1, Count("", Spec{Max: 5, Overlap: 1, Unit: Bytes}))
}

func TestSplitPanicsOnASpecThatCannotAdvance(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { Split("x", Spec{Max: 4, Overlap: 4}) })
	assert.Panics(t, func() { Count("x", Spec{Max: 0}) })
}

func TestSplitSurvivesInvalidUTF8(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("ab\xff\xfecd ", 400)
	for _, u := range []Unit{Bytes, UTF16} {
		spec := Spec{Max: 100, Overlap: 10, Unit: u}
		chunks := Split(text, spec)
		assert.Equal(t, len(chunks), Count(text, spec))
		assertOverlapGuarantee(t, text, spec, chunks)
	}
}

func FuzzSplitOverlapGuarantee(f *testing.F) {
	f.Add("hello wörld \U0001F600 日本語\r\nsecond line", uint8(40), uint8(5), false)
	f.Add(strings.Repeat("x", 300), uint8(33), uint8(7), true)
	f.Add(strings.Repeat("\U0001F600 ", 120), uint8(64), uint8(9), true)
	f.Add("a\xffb\n\n  c", uint8(12), uint8(3), false)
	f.Fuzz(func(t *testing.T, text string, max, overlap uint8, utf16 bool) {
		s := Spec{Max: int(max), Overlap: int(overlap), Unit: Bytes}
		if utf16 {
			s.Unit = UTF16
		}
		if s.Max < 12 || s.Overlap >= s.Max-8 {
			t.Skip()
		}
		chunks := assertInvariants(t, text, s)
		assertOverlapGuarantee(t, text, s, chunks)
	})
}
