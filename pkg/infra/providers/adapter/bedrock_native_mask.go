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
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// Substitution is one piece of text a plugin replaced.
//
// A text of minGlobalMaskLen characters or more is applied to every string of
// the body the view reads, and leak-checked everywhere. A shorter one, such as
// the two characters of "42", would rewrite unrelated text wherever it occurs, so
// it is applied only where the plugin changed it: Places names those spots.
type Substitution struct {
	From   string
	To     string
	Places []Place
}

// Place is one spot a short substitution was found at: the Target-th string the
// view reads in the body (in document order) and the byte offset of the removed
// text inside it.
type Place struct {
	Target int
	Off    int
}

const minGlobalMaskLen = 3

func (s Substitution) short() bool { return len(s.From) < minGlobalMaskLen }

// NativeMasker derives a mask from what a plugin did and applies it to the
// original bytes. The zero value is ready to use; Patch exists so that a test
// can prove a patcher that leaves text behind sends nothing.
type NativeMasker struct {
	Patch func(body []byte, subs []Substitution) ([]byte, error)
}

func (m NativeMasker) patch(body []byte, subs []Substitution) ([]byte, error) {
	if m.Patch != nil {
		return m.Patch(body, subs)
	}
	return patchInPlace(body, subs)
}

// MaskCause is why a mask could not be applied; the empty cause means it could.
// The caller forwards the original bytes and records the cause, so the values are
// stable tokens: they land in the failure reason of the event.
type MaskCause string

// The causes a mask can fail with.
const (
	MaskCauseDecode MaskCause = "decode_failed"
	// MaskCauseNotAReplacement: the policy added text, or changed something that
	// is not text, so there is nothing in the original to replace.
	MaskCauseNotAReplacement MaskCause = "not_a_text_replacement"
	// MaskCausePlaceUnknown: a value shorter than minGlobalMaskLen whose spot in the
	// original could not be established.
	MaskCausePlaceUnknown MaskCause = "short_value_place_unknown"
	MaskCauseSignedBlock  MaskCause = "signed_block"
	MaskCausePatch        MaskCause = "patch_failed"
	// MaskCauseOutsideReadStrings: something outside the strings the view reads
	// would have changed.
	MaskCauseOutsideReadStrings MaskCause = "outside_read_strings"
	MaskCauseShape              MaskCause = "shape_mismatch"
	MaskCauseLeak               MaskCause = "leak_remaining"
	MaskCauseErrorResponse      MaskCause = "error_response"

	// The causes below are the stream's.
	//
	// MaskCauseReasoning: the held frames carry model reasoning, which a text mask
	// cannot edit.
	MaskCauseReasoning MaskCause = "reasoning_not_maskable"
	// MaskCauseToolCallNotHeld: the held frames carry the input of a tool call the
	// guard could not hold whole, or of a family whose tool calls are not understood.
	MaskCauseToolCallNotHeld MaskCause = "tool_call_not_held"
	MaskCauseReleasedText    MaskCause = "already_released_text"
	// MaskCauseReleasedInput: the removed text is in tool input or reasoning that
	// was already released.
	MaskCauseReleasedInput MaskCause = "already_released_input"
	MaskCauseNoWindow      MaskCause = "no_inspected_window"
	// MaskCauseToolInput: the mask is not a replacement of text inside a string of
	// the tool input (a number, a key, a literal), or the input is not valid JSON or
	// does not read back exactly.
	MaskCauseToolInput  MaskCause = "tool_input_not_maskable"
	MaskCauseToolFrames MaskCause = "tool_frames_not_rewritable"
)

// MaskRequestWhy derives the mask from what a plugin did to the text it saw and
// carries it onto the original bytes; the plugin's own body is never sent, because
// it went through the canonical model and lost the fields that model does not
// hold. The mask is used only if the result, read again with the view, shows none
// of the removed text (of three characters or more), reads as the plugin's view,
// and changes nothing outside the strings the view reads. Otherwise it returns the
// cause, and the caller forwards the original and records why.
func (m NativeMasker) MaskRequestWhy(original, modified []byte) ([]byte, MaskCause) {
	a := &BedrockNativeAdapter{}
	before, err := a.DecodeRequest(original)
	if err != nil {
		return nil, MaskCauseDecode
	}
	after, err := a.DecodeRequest(modified)
	if err != nil {
		return nil, MaskCauseDecode
	}
	decode := func(b []byte) (string, error) {
		cr, err := a.DecodeRequest(b)
		if err != nil {
			return "", err
		}
		return requestText(cr), nil
	}
	subs, hits, ok := deriveSubstitutions(requestText(before), requestText(after))
	if !ok {
		return nil, MaskCauseNotAReplacement
	}
	if !placeShort(original, requestText(before), decode, subs, hits) {
		return nil, MaskCausePlaceUnknown
	}
	masked, err := m.patch(original, subs)
	if err != nil {
		return nil, patchCause(err)
	}
	got, err := a.DecodeRequest(masked)
	switch {
	case err != nil:
		return nil, MaskCauseDecode
	case !onlyReadStringsChanged(original, masked):
		return nil, MaskCauseOutsideReadStrings
	case !sameRequestShape(got, after):
		return nil, MaskCauseShape
	case leaks(requestText(got), subs) || treeLeaks(masked, subs):
		return nil, MaskCauseLeak
	}
	return masked, ""
}

func patchCause(err error) MaskCause {
	if errors.Is(err, errSignedBlock) {
		return MaskCauseSignedBlock
	}
	return MaskCausePatch
}

func (m NativeMasker) MaskResponseWhy(original, modified []byte) ([]byte, MaskCause) {
	a := &BedrockNativeAdapter{}
	before, err := a.DecodeResponse(original)
	if err != nil {
		return nil, MaskCauseDecode
	}
	after, err := a.DecodeResponse(modified)
	if err != nil {
		return nil, MaskCauseDecode
	}
	decode := func(b []byte) (string, error) {
		cr, err := a.DecodeResponse(b)
		if err != nil {
			return "", err
		}
		return cr.Content, nil
	}
	subs, hits, ok := deriveSubstitutions(before.Content, after.Content)
	if !ok {
		return nil, MaskCauseNotAReplacement
	}
	if !placeShort(original, before.Content, decode, subs, hits) {
		return nil, MaskCausePlaceUnknown
	}
	masked, err := m.patch(original, subs)
	if err != nil {
		return nil, patchCause(err)
	}
	got, err := a.DecodeResponse(masked)
	switch {
	case err != nil:
		return nil, MaskCauseDecode
	case !onlyReadStringsChanged(original, masked):
		return nil, MaskCauseOutsideReadStrings
	case !sameResponseShape(got, after):
		return nil, MaskCauseShape
	case leaks(got.Content, subs) || treeLeaks(masked, subs):
		return nil, MaskCauseLeak
	}
	return masked, ""
}

type hunkHit struct {
	start, end int
	sub        int
}

// deriveSubstitutions reads the replacements a plugin made off the text it saw.
func deriveSubstitutions(before, after string) ([]Substitution, []hunkHit, bool) {
	hunks, ok := diffText(before, after)
	if !ok {
		return nil, nil, false
	}
	var (
		subs []Substitution
		hits []hunkHit
	)
	seen := map[[2]string]int{}
	for _, h := range hunks {
		from, to := before[h.start:h.end], h.insert
		if strings.TrimSpace(from) == "" {
			if strings.TrimSpace(to) == "" {
				continue
			}
			return nil, nil, false
		}
		idx, dup := seen[[2]string{from, to}]
		if !dup {
			idx = len(subs)
			seen[[2]string{from, to}] = idx
			subs = append(subs, Substitution{From: from, To: to})
		}
		hits = append(hits, hunkHit{start: h.start, end: h.end, sub: idx})
	}
	return subs, hits, len(subs) > 0
}

// placeShort finds, for every spot a short substitution was made at, the string
// of the body it came from and the offset inside it, and records it on the
// substitution. It is not a search: the strings the view reads are tagged in a
// copy of the body, the same decoders read that copy, and the tags show where
// each string landed in the text the plugin saw. If the tags cannot be read
// back to exactly that text, or a spot falls in no single string, it reports
// false and the caller refuses the call.
func placeShort(body []byte, view string, decode func([]byte) (string, error), subs []Substitution, hits []hunkHit) bool {
	var spans []viewSpan
	known := false
	for _, h := range hits {
		if !subs[h.sub].short() {
			continue
		}
		if !known {
			var ok bool
			if spans, ok = viewSpans(body, view, decode); !ok {
				return false
			}
			known = true
		}
		found := false
		for _, sp := range spans {
			if sp.start <= h.start && h.end <= sp.end {
				place := Place{Target: sp.target, Off: h.start - sp.start}
				if !slicesHasPlace(subs[h.sub].Places, place) {
					subs[h.sub].Places = append(subs[h.sub].Places, place)
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func slicesHasPlace(places []Place, p Place) bool {
	for _, q := range places {
		if q == p {
			return true
		}
	}
	return false
}

// leaks reports whether any removed text is still in what a plugin would read.
func leaks(view string, subs []Substitution) bool {
	for _, s := range subs {
		if !s.short() && strings.TrimSpace(s.From) != "" && strings.Contains(view, s.From) {
			return true
		}
	}
	return false
}

func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// sameRequestShape holds when the masked original reads, in everything the
// plugin's body can carry, as that body does: its text apart from spacing, its
// tools and its sampling settings. A plugin that also removed a tool or changed
// a limit is doing more than masking, which a mask cannot reproduce.
func sameRequestShape(got, want *CanonicalRequest) bool {
	if normalizeSpace(requestText(got)) != normalizeSpace(requestText(want)) ||
		len(got.Tools) != len(want.Tools) || got.MaxTokens != want.MaxTokens ||
		!sameFloat(got.Temperature, want.Temperature) || !sameFloat(got.TopP, want.TopP) ||
		strings.Join(got.Stop, "\x00") != strings.Join(want.Stop, "\x00") {
		return false
	}
	for i := range got.Tools {
		if got.Tools[i].Name != want.Tools[i].Name {
			return false
		}
	}
	return true
}

func sameFloat(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func sameResponseShape(got, want *CanonicalResponse) bool {
	if normalizeSpace(got.Content) != normalizeSpace(want.Content) || len(got.ToolCalls) != len(want.ToolCalls) {
		return false
	}
	for i := range got.ToolCalls {
		if got.ToolCalls[i].Name != want.ToolCalls[i].Name {
			return false
		}
	}
	return true
}

func orderedForPatch(subs []Substitution) []Substitution {
	var out []Substitution
	for _, s := range subs {
		if len(s.From) >= minGlobalMaskLen {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].From) > len(out[j].From) })
	return out
}

func substituteString(s string, subs []Substitution) string {
	for _, sub := range subs {
		s = strings.ReplaceAll(s, sub.From, sub.To)
	}
	return s
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

type TextHunk struct {
	Start, End int
	Insert     string
}

// DiffText returns the replacements that turn before into after, as the
// substitution derivation reads them. ok is false when the texts differ too
// much to be read as a few replacements.
func DiffText(before, after string) ([]TextHunk, bool) {
	hunks, ok := diffText(before, after)
	if !ok {
		return nil, false
	}
	out := make([]TextHunk, len(hunks))
	for i, h := range hunks {
		out[i] = TextHunk{Start: h.start, End: h.end, Insert: h.insert}
	}
	return out, true
}

// DistributeHunks carries replacements found on the concatenation of texts back
// onto the pieces it was made of. A replacement lands whole in the first piece
// it touches and what it covered is taken out of the pieces after it, which may
// end up empty. The concatenation of the result is the concatenation of texts
// with the hunks applied.
func DistributeHunks(texts []string, hunks []TextHunk) []string {
	starts := make([]int, len(texts)+1)
	for i, t := range texts {
		starts[i+1] = starts[i] + len(t)
	}
	type edit struct {
		start, end int
		insert     string
	}
	edits := make([][]edit, len(texts))
	for _, h := range hunks {
		owner := len(texts) - 1
		for i := range texts {
			if h.Start < starts[i+1] {
				owner = i
				break
			}
		}
		for i := range texts {
			s, e := max(h.Start, starts[i]), min(h.End, starts[i+1])
			if s >= e && i != owner {
				continue
			}
			insert := ""
			if i == owner {
				insert = h.Insert
			}
			edits[i] = append(edits[i], edit{s - starts[i], e - starts[i], insert})
		}
	}
	out := make([]string, len(texts))
	for i, t := range texts {
		var sb strings.Builder
		cur := 0
		for _, ed := range edits[i] {
			sb.WriteString(t[cur:ed.start])
			sb.WriteString(ed.insert)
			cur = ed.end
		}
		sb.WriteString(t[cur:])
		out[i] = sb.String()
	}
	return out
}
