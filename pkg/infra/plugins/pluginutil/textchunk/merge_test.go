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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func maskEach(chunks []Chunk, edit func(string) string) []string {
	out := make([]string, len(chunks))
	for i, c := range chunks {
		out[i] = edit(c.Text)
	}
	return out
}

func TestMergeMasksAnEmailSeenWholeOnlyInTheSecondChunk(t *testing.T) {
	t.Parallel()
	pad := strings.Repeat("word ", 18)
	text := pad + "write to john.doe@example.com now " + strings.Repeat("tail ", 30)
	chunks := Split(text, Spec{Max: 120, Overlap: 40, Unit: Bytes})
	require.GreaterOrEqual(t, len(chunks), 2)
	masked := maskEach(chunks, func(s string) string {
		return strings.ReplaceAll(s, "john.doe@example.com", "<EMAIL>")
	})
	got, ok := MergeMasks(text, chunks, masked)
	require.True(t, ok)
	assert.Equal(t, strings.ReplaceAll(text, "john.doe@example.com", "<EMAIL>"), got)
	assert.NotContains(t, got, "john.doe")
}

func TestMergeMasksTheSameMaskSeenByTwoChunksIsAppliedOnce(t *testing.T) {
	t.Parallel()
	text := "aaaa SECRET bbbb"
	chunks := []Chunk{{Start: 0, End: 11, Text: text[:11]}, {Start: 5, End: 16, Text: text[5:]}}
	masked := []string{"aaaa [X]", "[X] bbbb"}
	got, ok := MergeMasks(text, chunks, masked)
	require.True(t, ok)
	assert.Equal(t, "aaaa [X] bbbb", got)
}

func TestMergeMasksConflictingSpansBecomeTheirUnionWithTheLongerInsert(t *testing.T) {
	t.Parallel()
	text := "see john.doe@exa.com ok"
	chunks := []Chunk{{Start: 0, End: 12, Text: text[:12]}, {Start: 4, End: 23, Text: text[4:]}}
	masked := []string{"see <PART>", "<EMAIL> ok"}
	got, ok := MergeMasks(text, chunks, masked)
	require.True(t, ok)
	assert.Equal(t, "see <EMAIL> ok", got)
	assert.NotContains(t, got, "john")
	assert.NotContains(t, got, "exa")
}

func TestMergeMasksAPlaceholderLongerOrShorterThanTheMatch(t *testing.T) {
	t.Parallel()
	text := "a 4111111111111111 b token-abc c"
	chunks := Split(text, Spec{Max: 1000, Overlap: 10, Unit: Bytes})
	masked := []string{"a <CREDIT_CARD_NUMBER_PLACEHOLDER> b # c"}
	got, ok := MergeMasks(text, chunks, masked)
	require.True(t, ok)
	assert.Equal(t, masked[0], got)
}

func TestMergeMasksUntouchedChunksReturnTheOriginal(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("plain ", 100)
	chunks := Split(text, Spec{Max: 100, Overlap: 10, Unit: Bytes})
	got, ok := MergeMasks(text, chunks, maskEach(chunks, func(s string) string { return s }))
	assert.True(t, ok)
	assert.Equal(t, text, got)
}

func TestMergeMasksTwoMasksInDifferentChunksBothApply(t *testing.T) {
	t.Parallel()
	text := "first AAA " + strings.Repeat("filler ", 60) + "second BBB end"
	chunks := Split(text, Spec{Max: 120, Overlap: 30, Unit: Bytes})
	require.Greater(t, len(chunks), 2)
	masked := maskEach(chunks, func(s string) string {
		return strings.NewReplacer("AAA", "<A>", "BBB", "<B>").Replace(s)
	})
	got, ok := MergeMasks(text, chunks, masked)
	require.True(t, ok)
	assert.Equal(t, strings.NewReplacer("AAA", "<A>", "BBB", "<B>").Replace(text), got)
}

func TestMergeMasksRefusesAMaskItCannotRead(t *testing.T) {
	t.Parallel()
	var b, c strings.Builder
	for i := 0; i < 700; i++ {
		b.WriteString("w")
		b.WriteString(strings.Repeat("a", i%7))
		b.WriteString(" ")
		c.WriteString("x")
		c.WriteString(strings.Repeat("b", i%5))
		c.WriteString(" ")
	}
	text := b.String()
	chunks := []Chunk{{Start: 0, End: len(text), Text: text}}
	_, ok := MergeMasks(text, chunks, []string{c.String()})
	assert.False(t, ok, "more than 512 edits is not a mask")
}

func TestMergeMasksRefusesAMismatchedSlice(t *testing.T) {
	t.Parallel()
	_, ok := MergeMasks("abc", []Chunk{{End: 3, Text: "abc"}}, nil)
	assert.False(t, ok)
}
