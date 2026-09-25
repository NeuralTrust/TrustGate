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
	"maps"
	"slices"
	"strconv"
	"strings"
)

const (
	probeOpen  = '\ue000'
	probeClose = '\ue001'
)

// probeKeys are the keys whose string values carry prompt text in the
// request formats the gateway speaks.
var probeKeys = map[string]bool{
	"text": true, "content": true, "refusal": true, "input": true,
	"instructions": true, "system": true, "output": true,
}

// graftedKeys are the top-level keys that hold prompt text or tools. They
// are edited in place, never replaced from the re-encoded body.
var graftedKeys = map[string]bool{
	"messages": true, "system": true, "instructions": true, "input": true,
	"contents": true, "systemInstruction": true, "tools": true, "toolConfig": true,
}

// GraftChangedFields returns the body a plugin should forward after editing
// mutated, where baseline is an untouched copy of the request decoded from
// original in the same format. Only the text blocks and tools whose
// canonical value changed are rewritten in original; every other byte stays,
// so fields the canonical model does not carry, key order and cache markers
// survive and the cached prefix is unchanged up to the first edit. Nothing
// changed returns original itself.
//
// A text edit is mapped back onto the client's blocks by their newline
// count. When that fails for a message, only that message's content is
// replaced by its re-encoded form. When the change cannot be placed at all
// (messages added or removed, fields other than text and tools changed, or a
// grafted body that does not decode to mutated), the result is mutated
// encoded in full, as before grafting existed.
func GraftChangedFields(ad RequestAdapter, original []byte, baseline, mutated *CanonicalRequest) ([]byte, error) {
	if ad == nil || mutated == nil {
		return nil, errors.New("graft: missing adapter or request")
	}
	if baseline != nil && bytes.Equal(canonicalJSON(baseline), canonicalJSON(mutated)) {
		return original, nil
	}
	encoded, err := ad.EncodeRequest(mutated)
	if err != nil {
		return nil, err
	}
	if baseline == nil {
		return encoded, nil
	}
	g := grafter{ad: ad, original: original, baseline: baseline, mutated: mutated, encoded: encoded}
	if out, ok := g.graft(); ok {
		return out, nil
	}
	return encoded, nil
}

// Clone returns a copy of r that shares no slice, map or cache marker with
// it, so a plugin can keep it as the baseline for GraftChangedFields while it
// edits r. Tool schemas, pointers to scalars and raw JSON values are shared:
// plugins replace those rather than edit them in place.
func (r *CanonicalRequest) Clone() *CanonicalRequest {
	if r == nil {
		return nil
	}
	c := *r
	c.SystemCache = cloneBreakpoint(r.SystemCache)
	c.Messages = slices.Clone(r.Messages)
	for i := range c.Messages {
		m := &c.Messages[i]
		m.Images = slices.Clone(m.Images)
		m.ToolCalls = slices.Clone(m.ToolCalls)
		m.Cache = cloneBreakpoint(m.Cache)
	}
	c.Tools = slices.Clone(r.Tools)
	for i := range c.Tools {
		c.Tools[i].Cache = cloneBreakpoint(c.Tools[i].Cache)
	}
	c.Stop = slices.Clone(r.Stop)
	if r.ToolChoice != nil {
		tc := *r.ToolChoice
		c.ToolChoice = &tc
	}
	if r.CacheOptions != nil {
		opts := *r.CacheOptions
		opts.Auto = cloneBreakpoint(opts.Auto)
		c.CacheOptions = &opts
	}
	c.Metadata = maps.Clone(r.Metadata)
	c.RequestExtensions = maps.Clone(r.RequestExtensions)
	return &c
}

func cloneBreakpoint(bp *CanonicalCacheBreakpoint) *CanonicalCacheBreakpoint {
	if bp == nil {
		return nil
	}
	c := *bp
	c.text = cloneBreakpoint(bp.text)
	return &c
}

func canonicalJSON(req *CanonicalRequest) []byte {
	b, err := json.Marshal(req)
	if err != nil {
		return nil
	}
	return b
}

type grafter struct {
	ad                RequestAdapter
	original          []byte
	baseline, mutated *CanonicalRequest
	encoded           []byte
}

type topEdit struct {
	value  []byte
	remove bool
}

func (g *grafter) graft() ([]byte, bool) {
	root, err := rawRoot(g.original)
	if err != nil || g.original[root.start] != '{' {
		return nil, false
	}
	if !bytes.Equal(canonicalJSON(withoutTextAndTools(g.baseline)), canonicalJSON(withoutTextAndTools(g.mutated))) {
		return nil, false
	}
	var patches []rawPatch
	if textChanged(g.baseline, g.mutated) {
		p, ok := g.textPatches(root)
		if !ok {
			return nil, false
		}
		patches = append(patches, p...)
	}
	top := map[string]topEdit{}
	if !bytes.Equal(toolsJSON(g.baseline.Tools), toolsJSON(g.mutated.Tools)) {
		p, ok := g.toolPatches(root, top)
		if !ok {
			return nil, false
		}
		patches = append(patches, p...)
	}
	topPatches, ok := rawObjectEdits(g.original, root, top)
	if !ok {
		return nil, false
	}
	out, err := applyRawPatches(g.original, append(patches, topPatches...))
	if err != nil {
		return nil, false
	}
	return out, g.faithful(out)
}

// faithful reports whether out means what mutated means, directly or as the
// full re-encode would carry it (an encoder may drop a tool_choice that names
// a removed tool, for one).
func (g *grafter) faithful(out []byte) bool {
	decoded, err := g.ad.DecodeRequest(out)
	if err != nil || decoded == nil {
		return false
	}
	got := canonicalJSON(decoded)
	if bytes.Equal(got, canonicalJSON(g.mutated)) {
		return true
	}
	reencoded, err := g.ad.DecodeRequest(g.encoded)
	return err == nil && reencoded != nil && bytes.Equal(got, canonicalJSON(reencoded))
}

func withoutTextAndTools(r *CanonicalRequest) *CanonicalRequest {
	c := *r
	c.System, c.Tools = "", nil
	c.Messages = make([]CanonicalMessage, len(r.Messages))
	for i, m := range r.Messages {
		m.Content = ""
		c.Messages[i] = m
	}
	return &c
}

func textChanged(a, b *CanonicalRequest) bool {
	if a.System != b.System {
		return true
	}
	for i := range a.Messages {
		if a.Messages[i].Content != b.Messages[i].Content {
			return true
		}
	}
	return false
}

func fieldText(r *CanonicalRequest, field int) string {
	if field == 0 {
		return r.System
	}
	return r.Messages[field-1].Content
}

func rawObjectEdits(b []byte, obj rawSpan, edits map[string]topEdit) ([]rawPatch, bool) {
	if len(edits) == 0 {
		return nil, true
	}
	fields, err := rawFields(b, obj)
	if err != nil {
		return nil, false
	}
	entries := make([]rawSpan, len(fields))
	drop := make([]bool, len(fields))
	replace := map[int][]byte{}
	seen := map[string]bool{}
	for i, f := range fields {
		entries[i] = f.entry
		e, ok := edits[f.key]
		if !ok {
			continue
		}
		if e.remove || seen[f.key] {
			drop[i] = true
			continue
		}
		seen[f.key] = true
		replace[i] = append(append([]byte(nil), b[f.entry.start:f.value.start]...), e.value...)
	}
	var added [][]byte
	for _, key := range slices.Sorted(maps.Keys(edits)) {
		if e := edits[key]; !e.remove && !seen[key] {
			added = append(added, append(append(marshalRawString(key), ':'), e.value...))
		}
	}
	return rawListEdits(entries, obj.end-1, drop, replace, added), true
}

// textProbe maps the prompt text of a body onto its string values: each
// non-blank string under a probe key is swapped for a numbered sentinel and
// the body is decoded again, so the decoder itself reports which values make
// up the system text and each message, and with which joiners.
type textProbe struct {
	leaves []probeLeaf
	fields []probeTemplate
}

type probeLeaf struct {
	path  []string
	span  rawSpan
	value string
}

type probeTemplate []probeItem

type probeItem struct {
	lit string
	ref int
}

func probeText(ad RequestAdapter, body []byte, root rawSpan) (*textProbe, bool) {
	var leaves []probeLeaf
	if collectProbeLeaves(body, root, nil, "", &leaves) != nil {
		return nil, false
	}
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

func collectProbeLeaves(b []byte, s rawSpan, path []string, key string, out *[]probeLeaf) error {
	switch b[s.start] {
	case '"':
		if !probeKeys[key] {
			return nil
		}
		value, ok := rawString(b, s)
		if !ok {
			return errRawJSON
		}
		if strings.TrimSpace(value) != "" {
			*out = append(*out, probeLeaf{path: slices.Clone(path), span: s, value: value})
		}
	case '{':
		fields, err := rawFields(b, s)
		if err != nil {
			return err
		}
		for _, f := range fields {
			if err := collectProbeLeaves(b, f.value, append(path, f.key), f.key, out); err != nil {
				return err
			}
		}
	case '[':
		items, err := rawItems(b, s)
		if err != nil {
			return err
		}
		for i, item := range items {
			if err := collectProbeLeaves(b, item, append(path, strconv.Itoa(i)), "", out); err != nil {
				return err
			}
		}
	}
	return nil
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
	var sb strings.Builder
	for _, it := range t {
		if it.ref < 0 {
			sb.WriteString(it.lit)
		} else {
			sb.WriteString(leaves[it.ref].value)
		}
	}
	return sb.String()
}

// distribute splits text over the template's values by giving each value
// the newline count it had, the way decoders joined the blocks. A value must
// be followed by a joiner that starts with "\n" or end the text; anything
// else is ambiguous and refused.
func (t probeTemplate) distribute(leaves []probeLeaf, text string) (map[int]string, bool) {
	values := map[int]string{}
	pos := 0
	for k, it := range t {
		if it.ref < 0 {
			if !strings.HasPrefix(text[pos:], it.lit) {
				return nil, false
			}
			pos += len(it.lit)
			continue
		}
		if _, dup := values[it.ref]; dup {
			return nil, false
		}
		if k == len(t)-1 {
			values[it.ref] = text[pos:]
			pos = len(text)
			continue
		}
		if next := t[k+1]; next.ref >= 0 || !strings.HasPrefix(next.lit, "\n") {
			return nil, false
		}
		end, ok := newlineAfter(text[pos:], strings.Count(leaves[it.ref].value, "\n"))
		if !ok {
			return nil, false
		}
		values[it.ref] = text[pos : pos+end]
		pos += end
	}
	return values, pos == len(text)
}

func newlineAfter(s string, lines int) (int, bool) {
	at := 0
	for range lines + 1 {
		i := strings.IndexByte(s[at:], '\n')
		if i < 0 {
			return 0, false
		}
		at += i + 1
	}
	return at - 1, true
}

func (g *grafter) textPatches(root rawSpan) ([]rawPatch, bool) {
	p, ok := probeText(g.ad, g.original, root)
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
		if t.render(p.leaves) == before {
			if split, ok := t.distribute(p.leaves, after); ok {
				maps.Copy(values, split)
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
	contents, ok := g.reencodedContents(root, p, owners, reencode)
	if !ok {
		return nil, false
	}
	return append(patches, contents...), true
}

// reencodedContents replaces, for each field, the smallest value of original
// that holds all of its text and nothing of another field's (a message's
// content) with the same value of the full re-encode.
func (g *grafter) reencodedContents(root rawSpan, p *textProbe, owners map[int][]int, fields []int) ([]rawPatch, bool) {
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
		path, ok := exclusiveContainer(p, owners, f)
		if !ok {
			return nil, false
		}
		encPath, ok := exclusiveContainer(pe, encOwners, f)
		if !ok || path[len(path)-1] != encPath[len(encPath)-1] {
			return nil, false
		}
		at, ok := rawAt(g.original, root, path)
		if !ok {
			return nil, false
		}
		from, ok := rawAt(g.encoded, encRoot, encPath)
		if !ok {
			return nil, false
		}
		patches = append(patches, rawPatch{at: at, with: g.encoded[from.start:from.end]})
	}
	return patches, true
}

func exclusiveContainer(p *textProbe, owners map[int][]int, field int) ([]string, bool) {
	refs := p.fields[field].refs()
	if len(refs) == 0 {
		return nil, false
	}
	prefix := p.leaves[refs[0]].path
	for _, ref := range refs[1:] {
		prefix = commonPrefix(prefix, p.leaves[ref].path)
	}
	if len(prefix) < 2 {
		return nil, false
	}
	for ref, l := range p.leaves {
		if len(l.path) < len(prefix) || !slices.Equal(l.path[:len(prefix)], prefix) {
			continue
		}
		if fs := owners[ref]; len(fs) != 1 || fs[0] != field {
			return nil, false
		}
	}
	return prefix, true
}

func commonPrefix(a, b []string) []string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n]
}
