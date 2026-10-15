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
	"strings"
)

const (
	probeOpen  = '\ue000'
	probeClose = '\ue001'

	maxGraftBody   = 8 << 20
	maxGraftValues = 250_000
	maxGraftDepth  = 64
	maxGraftRescan = 16
)

// probeKeys are the keys whose string values carry prompt text in the
// request formats the gateway speaks. They match ignoring case, as
// encoding/json matches struct fields.
var probeKeys = []string{"text", "content", "refusal", "input", "instructions", "system", "output", "tool_plan"}

func isProbeKey(key string) bool {
	for _, k := range probeKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}

// graftedKeys are the top-level keys that hold prompt text or tools. They
// are edited in place, never replaced from the re-encoded body.
var graftedKeys = map[string]bool{
	"messages": true, "system": true, "instructions": true, "input": true,
	"contents": true, "systemInstruction": true, "system_instruction": true, "tools": true,
}

// GraftOptions tunes GraftChangedFieldsWith for the plugin making the edit.
type GraftOptions struct {
	// KeepUnmodelledTool reports whether a tools entry the canonical request
	// does not model (a built-in or server tool such as mcp or web_search, a
	// legacy Chat function, an Anthropic MCP server) stays in the body. The
	// entry is as UnmodelledTools reports it. When set, it is applied even if
	// the modelled tools did not change, so an entry it refuses is always
	// removed. Nil keeps every such entry while the tools are unchanged and
	// drops the tools entries when they change; a full re-encode drops them
	// all.
	KeepUnmodelledTool func(UnmodelledTool) bool
}

// GraftChangedFields is GraftChangedFieldsWith with the default options:
// unmodelled tools are dropped when the tools change.
func GraftChangedFields(ad RequestAdapter, original []byte, baseline, mutated *CanonicalRequest) ([]byte, error) {
	return GraftChangedFieldsWith(ad, original, baseline, mutated, GraftOptions{})
}

// GraftChangedFieldsWith returns the body a plugin should forward after
// editing mutated, where baseline is an untouched copy of the request
// decoded from original in the same format. Only the text blocks and tools
// whose canonical value changed are rewritten in original; every other byte
// stays, so fields the canonical model does not carry, key order and cache
// markers survive and the cached prefix is unchanged up to the first edit.
// Nothing changed returns original itself, unless HasAmbiguousKeys reports
// it.
//
// Grafting is for edits that add, remove or reword content the upstream may
// see anyway (tools, compressed whitespace). A redaction must encode mutated
// in full instead: text it removes can have copies in fields the canonical
// request does not model, which a graft keeps and a re-encode drops.
//
// A text edit is diffed against the text it replaces and each changed run
// is written into the block that holds it. When a run crosses a block
// boundary, only that message's content is replaced by its re-encoded form.
// The result is mutated encoded in full, as before grafting existed, when
// the change cannot be placed: messages added or removed, fields other than
// text and tools changed, a body HasAmbiguousKeys reports or over the size,
// value or nesting caps (the raw walks rescan a value at each level above
// it), or a grafted body that does not decode to mutated.
func GraftChangedFieldsWith(ad RequestAdapter, original []byte, baseline, mutated *CanonicalRequest, opts GraftOptions) ([]byte, error) {
	if ad == nil || mutated == nil {
		return nil, errors.New("graft: missing adapter or request")
	}
	var g *grafter
	if baseline != nil {
		g = newGrafter(ad, original, baseline, mutated, opts)
		if g.unchanged() && !g.ambiguous {
			return original, nil
		}
	}
	encoded, err := ad.EncodeRequest(mutated)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return encoded, nil
	}
	g.encoded = encoded
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
	opts              GraftOptions
	bedrock           bool

	orig                        rawToolList
	origRead, origFound, origOK bool

	sameRest, textChanged, toolsChanged bool

	// shape is the key shape of original, which a graft keeps: it edits no
	// top-level key the Chat adapter dispatches on. ambiguous is
	// HasAmbiguousKeys for original.
	shape     *keyShape
	ambiguous bool
}

type topEdit struct {
	value  []byte
	remove bool
}

func newGrafter(ad RequestAdapter, original []byte, baseline, mutated *CanonicalRequest, opts GraftOptions) *grafter {
	_, bedrock := ad.(*BedrockAdapter)
	g := &grafter{ad: ad, original: original, baseline: baseline, mutated: mutated, opts: opts, bedrock: bedrock}
	g.shape = keyShapeFor(adapterFormat(ad), original)
	g.ambiguous = !decodableBody(original) || ambiguousKeys(original, g.shape)
	g.sameRest = bytes.Equal(canonicalJSON(withoutTextAndTools(baseline)), canonicalJSON(withoutTextAndTools(mutated)))
	g.textChanged = g.sameRest && textChanged(baseline, mutated)
	g.toolsChanged = !sameTools(baseline.Tools, mutated.Tools) || !sameToolChoice(baseline.ToolChoice, mutated.ToolChoice) ||
		g.refusesUnmodelledTool()
	return g
}

func (g *grafter) unchanged() bool {
	return g.sameRest && !g.textChanged && !g.toolsChanged
}

func (g *grafter) graft() ([]byte, bool) {
	if !g.sameRest || len(g.original) > maxGraftBody || g.ambiguous {
		return nil, false
	}
	root, err := rawRoot(g.original)
	if err != nil || g.original[root.start] != '{' {
		return nil, false
	}
	idx, ok := indexLeaves(g.original, root)
	if !ok {
		return nil, false
	}
	var patches []rawPatch
	if g.textChanged {
		p, ok := g.textPatches(idx)
		if !ok {
			return nil, false
		}
		patches = append(patches, p...)
	}
	top := map[string]topEdit{}
	if g.toolsChanged {
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
	if err != nil || !g.faithful(out) || ambiguousKeys(out, g.shape) {
		return nil, false
	}
	return out, true
}

// faithful reports whether out means what mutated means, directly or as the
// full re-encode would carry it (an encoder may drop a tool_choice that names
// a removed tool, for one). out must decode, which also proves it valid JSON
// before ambiguousKeys scans it.
func (g *grafter) faithful(out []byte) bool {
	decoded, err := g.ad.DecodeRequest(out)
	if err != nil || decoded == nil {
		return false
	}
	if sameRequest(decoded, g.mutated) {
		return true
	}
	reencoded, err := g.ad.DecodeRequest(g.encoded)
	return err == nil && reencoded != nil && sameRequest(decoded, reencoded)
}

// sameRequest reports whether a and b encode alike, comparing text and tools
// directly rather than through their JSON.
func sameRequest(a, b *CanonicalRequest) bool {
	if len(a.Messages) != len(b.Messages) || textChanged(a, b) || !sameTools(a.Tools, b.Tools) ||
		!sameToolChoice(a.ToolChoice, b.ToolChoice) {
		return false
	}
	return bytes.Equal(canonicalJSON(withoutTextAndTools(a)), canonicalJSON(withoutTextAndTools(b)))
}

func sameToolChoice(a, b *CanonicalToolChoice) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// withoutTextAndTools is r without the text and tool fields a graft edits in
// place.
func withoutTextAndTools(r *CanonicalRequest) *CanonicalRequest {
	c := *r
	c.System, c.Tools, c.ToolChoice = "", nil, nil
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
	byFold := make(map[string]string, len(edits))
	for key := range edits {
		byFold[foldKey(key)] = key
	}
	entries := make([]rawSpan, len(fields))
	drop := make([]bool, len(fields))
	replace := map[int][]byte{}
	seen := map[string]bool{}
	for i, f := range fields {
		entries[i] = f.entry
		key, ok := byFold[foldKey(f.key)]
		if !ok {
			continue
		}
		e := edits[key]
		if e.remove || seen[key] {
			drop[i] = true
			continue
		}
		seen[key] = true
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
