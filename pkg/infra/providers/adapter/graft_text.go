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
	"maps"
	"slices"
	"strconv"
	"strings"
)

// textProbe maps the prompt text of a body onto its string values: each
// non-blank string under a probe key is swapped for a numbered sentinel and
// the body is decoded again, so the decoder itself reports which values make
// up the system text and each message, and with which joiners.
type textProbe struct {
	leaves []probeLeaf
	fields []probeTemplate
}

// probeLeaf is one probed string value. spans[i] is the span of the value
// at path[:i+1], so any container of the leaf is found without walking the
// body again.
type probeLeaf struct {
	path  []string
	spans []rawSpan
	span  rawSpan
	value string
}

type probeTemplate []probeItem

type probeItem struct {
	lit string
	ref int
}

func probeText(ad RequestAdapter, body []byte, root rawSpan) (*textProbe, bool) {
	leaves, ok := indexLeaves(body, root)
	if !ok {
		return nil, false
	}
	return probeLeaves(ad, body, leaves)
}

func probeLeaves(ad RequestAdapter, body []byte, leaves []probeLeaf) (*textProbe, bool) {
	patches := make([]rawPatch, len(leaves))
	for i, l := range leaves {
		if strings.ContainsRune(l.value, probeOpen) || strings.ContainsRune(l.value, probeClose) {
			return nil, false
		}
		patches[i] = rawPatch{at: l.span, with: marshalRawString(string(probeOpen) + strconv.Itoa(i) + string(probeClose))}
	}
	probed, err := applyRawPatches(body, patches)
	if err != nil {
		return nil, false
	}
	decoded, err := ad.DecodeRequest(probed)
	if err != nil || decoded == nil {
		return nil, false
	}
	p := &textProbe{leaves: leaves, fields: make([]probeTemplate, 0, len(decoded.Messages)+1)}
	texts := []string{decoded.System}
	for _, m := range decoded.Messages {
		texts = append(texts, m.Content)
	}
	for _, text := range texts {
		t, ok := parseProbeTemplate(text, len(leaves))
		if !ok {
			return nil, false
		}
		p.fields = append(p.fields, t)
	}
	return p, true
}

// indexLeaves walks a valid JSON body once and returns its probe leaves in
// document order. It refuses bodies with duplicate keys or more than
// maxGraftValues values.
func indexLeaves(b []byte, root rawSpan) ([]probeLeaf, bool) {
	x := leafIndexer{b: b}
	if !x.walk(root, "") {
		return nil, false
	}
	return x.leaves, true
}

type leafIndexer struct {
	b      []byte
	path   []string
	spans  []rawSpan
	values int
	leaves []probeLeaf
}

func (x *leafIndexer) walk(s rawSpan, key string) bool {
	if x.values++; x.values > maxGraftValues {
		return false
	}
	switch x.b[s.start] {
	case '"':
		if !isProbeKey(key) {
			return true
		}
		value, ok := rawString(x.b, s)
		if !ok {
			return false
		}
		if strings.TrimSpace(value) != "" {
			x.leaves = append(x.leaves, probeLeaf{path: slices.Clone(x.path), spans: slices.Clone(x.spans), span: s, value: value})
		}
	case '{':
		fields, err := rawFields(x.b, s)
		if err != nil {
			return false
		}
		for _, f := range fields {
			if !x.child(f.value, f.key, f.key) {
				return false
			}
		}
	case '[':
		items, err := rawItems(x.b, s)
		if err != nil {
			return false
		}
		for i, item := range items {
			if !x.child(item, strconv.Itoa(i), "") {
				return false
			}
		}
	}
	return true
}

func (x *leafIndexer) child(s rawSpan, step, key string) bool {
	x.path = append(x.path, step)
	x.spans = append(x.spans, s)
	ok := x.walk(s, key)
	x.path = x.path[:len(x.path)-1]
	x.spans = x.spans[:len(x.spans)-1]
	return ok
}

func parseProbeTemplate(text string, leaves int) (probeTemplate, bool) {
	var t probeTemplate
	for text != "" {
		open := strings.IndexRune(text, probeOpen)
		if open < 0 {
			return append(t, probeItem{lit: text, ref: -1}), true
		}
		if open > 0 {
			t = append(t, probeItem{lit: text[:open], ref: -1})
		}
		rest := text[open+len(string(probeOpen)):]
		end := strings.IndexRune(rest, probeClose)
		if end < 0 {
			return nil, false
		}
		ref, err := strconv.Atoi(rest[:end])
		if err != nil || ref < 0 || ref >= leaves {
			return nil, false
		}
		t = append(t, probeItem{ref: ref})
		text = rest[end+len(string(probeClose)):]
	}
	return t, true
}

func (t probeTemplate) refs() []int {
	var refs []int
	for _, it := range t {
		if it.ref >= 0 {
			refs = append(refs, it.ref)
		}
	}
	return refs
}

func (t probeTemplate) render(leaves []probeLeaf) string {
	return t.renderWith(leaves, nil)
}

func (t probeTemplate) renderWith(leaves []probeLeaf, values map[int]string) string {
	var sb strings.Builder
	for _, it := range t {
		switch v, ok := values[it.ref]; {
		case it.ref < 0:
			sb.WriteString(it.lit)
		case ok:
			sb.WriteString(v)
		default:
			sb.WriteString(leaves[it.ref].value)
		}
	}
	return sb.String()
}

// place writes each hunk into the value that holds it, by the character
// offsets of the values in the text the template renders. A hunk that
// touches a joiner or spans two values is refused, so an edit never moves
// text, or the cache marker after it, from one block into another.
func (t probeTemplate) place(leaves []probeLeaf, hunks []textHunk) (map[int]string, bool) {
	type seg struct{ ref, start, end int }
	segs := make([]seg, 0, len(t))
	seen := map[int]bool{}
	pos := 0
	for _, it := range t {
		if it.ref < 0 {
			pos += len(it.lit)
			continue
		}
		if seen[it.ref] {
			return nil, false
		}
		seen[it.ref] = true
		n := len(leaves[it.ref].value)
		segs = append(segs, seg{ref: it.ref, start: pos, end: pos + n})
		pos += n
	}
	edits := map[int][]textHunk{}
	si := 0
	for _, h := range hunks {
		for si < len(segs) && (segs[si].end < h.start || (segs[si].end == h.start && h.end > h.start)) {
			si++
		}
		if si == len(segs) || h.start < segs[si].start || h.end > segs[si].end {
			return nil, false
		}
		s := segs[si]
		edits[s.ref] = append(edits[s.ref], textHunk{start: h.start - s.start, end: h.end - s.start, insert: h.insert})
	}
	values := make(map[int]string, len(edits))
	for ref, hs := range edits {
		v := leaves[ref].value
		var sb strings.Builder
		last := 0
		for _, h := range hs {
			sb.WriteString(v[last:h.start])
			sb.WriteString(h.insert)
			last = h.end
		}
		sb.WriteString(v[last:])
		values[ref] = sb.String()
	}
	return values, true
}

func (g *grafter) textPatches(leaves []probeLeaf) ([]rawPatch, bool) {
	p, ok := probeLeaves(g.ad, g.original, leaves)
	if !ok || len(p.fields) != len(g.baseline.Messages)+1 {
		return nil, false
	}
	owners := make(map[int][]int, len(p.leaves))
	for f, t := range p.fields {
		for _, ref := range t.refs() {
			owners[ref] = append(owners[ref], f)
		}
	}
	values := map[int]string{}
	var reencode []int
	for f, t := range p.fields {
		before, after := fieldText(g.baseline, f), fieldText(g.mutated, f)
		if before == after {
			continue
		}
		for _, ref := range t.refs() {
			if len(owners[ref]) > 1 {
				return nil, false
			}
		}
		hunks, ok := diffText(before, after)
		if !ok {
			return nil, false
		}
		g.notePieces(before, hunks)
		if t.render(p.leaves) == before {
			if placed, ok := t.place(p.leaves, hunks); ok && t.renderWith(p.leaves, placed) == after {
				maps.Copy(values, placed)
				continue
			}
		}
		if f == 0 {
			return nil, false
		}
		reencode = append(reencode, f)
	}
	var patches []rawPatch
	for ref, v := range values {
		if v != p.leaves[ref].value {
			patches = append(patches, rawPatch{at: p.leaves[ref].span, with: marshalRawString(v)})
		}
	}
	if len(reencode) == 0 {
		return patches, true
	}
	contents, ok := g.reencodedContents(p, owners, reencode)
	if !ok {
		return nil, false
	}
	return append(patches, contents...), true
}

// reencodedContents replaces, for each field, the smallest value of original
// that holds all of its text and nothing of another field's (a message's
// content) with the same value of the full re-encode.
func (g *grafter) reencodedContents(p *textProbe, owners map[int][]int, fields []int) ([]rawPatch, bool) {
	encRoot, err := rawRoot(g.encoded)
	if err != nil {
		return nil, false
	}
	pe, ok := probeText(g.ad, g.encoded, encRoot)
	if !ok || len(pe.fields) != len(g.mutated.Messages)+1 {
		return nil, false
	}
	encOwners := map[int][]int{}
	for f, t := range pe.fields {
		for _, ref := range t.refs() {
			encOwners[ref] = append(encOwners[ref], f)
		}
	}
	patches := make([]rawPatch, 0, len(fields))
	for _, f := range fields {
		path, at, ok := exclusiveContainer(p, owners, f)
		if !ok {
			return nil, false
		}
		encPath, from, ok := exclusiveContainer(pe, encOwners, f)
		if !ok || path[len(path)-1] != encPath[len(encPath)-1] {
			return nil, false
		}
		patches = append(patches, rawPatch{at: at, with: g.encoded[from.start:from.end]})
	}
	return patches, true
}

// exclusiveContainer returns the path and span of the deepest value that
// holds every leaf of field and only leaves owned by it. Leaves are in
// document order, so the leaves under one container are contiguous.
func exclusiveContainer(p *textProbe, owners map[int][]int, field int) ([]string, rawSpan, bool) {
	refs := p.fields[field].refs()
	if len(refs) == 0 {
		return nil, rawSpan{}, false
	}
	lo, hi := refs[0], refs[0]
	prefix := p.leaves[refs[0]].path
	for _, ref := range refs[1:] {
		prefix = commonPrefix(prefix, p.leaves[ref].path)
		lo, hi = min(lo, ref), max(hi, ref)
	}
	if len(prefix) < 2 {
		return nil, rawSpan{}, false
	}
	under := func(i int) bool {
		path := p.leaves[i].path
		return len(path) >= len(prefix) && slices.Equal(path[:len(prefix)], prefix)
	}
	for lo > 0 && under(lo-1) {
		lo--
	}
	for hi+1 < len(p.leaves) && under(hi+1) {
		hi++
	}
	for ref := lo; ref <= hi; ref++ {
		if fs := owners[ref]; len(fs) != 1 || fs[0] != field {
			return nil, rawSpan{}, false
		}
	}
	return prefix, p.leaves[refs[0]].spans[len(prefix)-1], true
}

func commonPrefix(a, b []string) []string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n]
}
