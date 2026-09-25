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
	"maps"
	"strings"
)

// FilterTools returns the tools keep accepts, in their original order. The
// cache marker of a removed tool moves to the nearest kept tool before it,
// keeping the longer TTL when that tool has a marker of its own, so the tool
// prefix the client marked stays cached up to what is left of it. A marker
// with no kept tool before it is dropped.
func FilterTools(tools []CanonicalTool, keep func(CanonicalTool) bool) []CanonicalTool {
	kept := make([]CanonicalTool, 0, len(tools))
	for _, t := range tools {
		if keep(t) {
			kept = append(kept, t)
			continue
		}
		if t.Cache == nil || len(kept) == 0 {
			continue
		}
		last := &kept[len(kept)-1]
		last.Cache = laterCacheBreakpoint(last.Cache, &CanonicalCacheBreakpoint{TTL: t.Cache.TTL})
	}
	return kept
}

func toolsJSON(tools []CanonicalTool) []byte {
	b, err := json.Marshal(tools)
	if err != nil {
		return nil
	}
	return b
}

type rawTool struct {
	name       string
	kind       string
	item       int
	trailers   []int
	unmodelled bool
}

// UnmodelledToolKinds returns the kind of each tools entry of body that req,
// decoded from body by ad, does not carry: a built-in or server tool such as
// mcp or web_search. The kind is the entry's "type", or its only key, or ""
// when it has neither. An entry sharing its name with more entries than req
// has tools of that name counts as unmodelled too, since which one req
// carries is unknown. ok is false when the tools cannot be read.
func UnmodelledToolKinds(ad RequestAdapter, body []byte, req *CanonicalRequest) ([]string, bool) {
	if ad == nil || req == nil {
		return nil, false
	}
	root, err := rawRoot(body)
	if err != nil || body[root.start] != '{' {
		return nil, false
	}
	_, tools, found, ok := rawToolsOf(ad, body, root, req.Tools)
	if !ok || !found {
		return nil, ok
	}
	var kinds []string
	for _, t := range tools {
		if t.unmodelled {
			kinds = append(kinds, t.kind)
		}
	}
	return kinds, true
}

func toolsPath(ad RequestAdapter) (string, []string) {
	if _, bedrock := ad.(*BedrockAdapter); bedrock {
		return "toolConfig", []string{"toolConfig", "tools"}
	}
	return "tools", []string{"tools"}
}

// rawToolsOf reads the tools array of the object at root and marks the
// entries modelled does not carry. found is false when there is no array.
func rawToolsOf(ad RequestAdapter, b []byte, root rawSpan, modelled []CanonicalTool) ([]rawSpan, []rawTool, bool, bool) {
	_, path := toolsPath(ad)
	arr, found := rawAt(b, root, path)
	if !found || string(b[arr.start:arr.end]) == "null" {
		return nil, nil, false, true
	}
	items, tools, ok := rawToolEntries(b, arr)
	if !ok {
		return nil, nil, true, false
	}
	_, gemini := ad.(*GeminiAdapter)
	markUnmodelled(b, items, tools, modelled, gemini)
	return items, tools, true, true
}

func markUnmodelled(b []byte, items []rawSpan, tools []rawTool, modelled []CanonicalTool, gemini bool) {
	want := map[string]int{}
	for _, t := range modelled {
		want[t.Name]++
	}
	have := map[string]int{}
	for _, t := range tools {
		have[t.name]++
	}
	for i := range tools {
		t := &tools[i]
		t.kind = rawToolKind(b, items[t.item])
		if gemini {
			t.unmodelled = !geminiDeclarations(b, items[t.item])
		} else {
			t.unmodelled = t.name == "" || have[t.name] > want[t.name]
		}
	}
}

// geminiDeclarations reports a Gemini tools entry that holds nothing but the
// function declarations the adapter decodes.
func geminiDeclarations(b []byte, item rawSpan) bool {
	if b[item.start] != '{' {
		return false
	}
	fields, err := rawFields(b, item)
	if err != nil || len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !strings.EqualFold(f.key, "functionDeclarations") {
			return false
		}
	}
	return true
}

// refusesUnmodelledTool reports whether KeepUnmodelledTool refuses a tools
// entry of original the baseline does not carry, which must then go even
// though the modelled tools are unchanged. A body whose tools cannot be read
// counts as refused, so the full re-encode drops them.
func (g *grafter) refusesUnmodelledTool() bool {
	if g.opts.KeepUnmodelledTool == nil {
		return false
	}
	kinds, ok := UnmodelledToolKinds(g.ad, g.original, g.baseline)
	if !ok {
		return true
	}
	for _, kind := range kinds {
		if !g.opts.KeepUnmodelledTool(kind) {
			return true
		}
	}
	return false
}

// toolPatches edits the tools array of original entry by entry: unchanged
// tools keep their bytes, changed ones take their re-encoded form, removed
// ones go and new ones are appended. Tools the canonical model does not
// carry stay only when GraftOptions.KeepUnmodelledTool keeps them. Top-level
// keys the tool change touched in the re-encode (a tool_choice that named a
// removed tool) are recorded in top. When the entries cannot be matched by
// name, the whole tools value is replaced by the re-encoded one followed by
// the unmodelled entries that stay.
func (g *grafter) toolPatches(root rawSpan, top map[string]topEdit) ([]rawPatch, bool) {
	encRoot, err := rawRoot(g.encoded)
	if err != nil {
		return nil, false
	}
	if !g.otherTopEdits(encRoot, top) {
		return nil, false
	}
	topKey, path := toolsPath(g.ad)
	origItems, origTools, hasOrig, ok := rawToolsOf(g.ad, g.original, root, g.baseline.Tools)
	if !ok {
		return nil, false
	}
	var kept [][]byte
	for _, rt := range origTools {
		if rt.unmodelled && g.keepUnmodelled(rt.kind) {
			it := origItems[rt.item]
			kept = append(kept, g.original[it.start:it.end])
		}
	}
	origArr, _ := rawAt(g.original, root, path)
	encArr, hasEnc := rawAt(g.encoded, encRoot, path)
	if !hasOrig || !hasEnc || len(g.mutated.Tools) == 0 {
		switch v, ok := rawFieldOf(g.encoded, encRoot, topKey); {
		case len(kept) > 0 && hasOrig && !g.bedrock:
			top[topKey] = topEdit{value: joinRawArray(nil, kept)}
		case ok:
			top[topKey] = topEdit{value: g.encoded[v.start:v.end]}
		default:
			top[topKey] = topEdit{remove: true}
		}
		return nil, true
	}
	if patches, ok := g.toolEntryPatches(origArr, origItems, origTools, encArr); ok {
		return patches, true
	}
	encItems, err := rawItems(g.encoded, encArr)
	if err != nil {
		return nil, false
	}
	whole := make([][]byte, 0, len(encItems)+len(kept))
	for _, it := range encItems {
		whole = append(whole, g.encoded[it.start:it.end])
	}
	return []rawPatch{{at: origArr, with: joinRawArray(whole, kept)}}, true
}

func joinRawArray(a, b [][]byte) []byte {
	return append(append([]byte{'['}, bytes.Join(append(a, b...), []byte(","))...), ']')
}

func (g *grafter) otherTopEdits(encRoot rawSpan, top map[string]topEdit) bool {
	before, err := g.ad.EncodeRequest(g.baseline)
	if err != nil {
		return false
	}
	beforeRoot, err := rawRoot(before)
	if err != nil {
		return false
	}
	was, ok := rawValues(before, beforeRoot)
	if !ok {
		return false
	}
	now, ok := rawValues(g.encoded, encRoot)
	if !ok {
		return false
	}
	keys := maps.Clone(was)
	maps.Copy(keys, now)
	for key := range keys {
		if graftedKeys[key] || (g.bedrock && key == "toolConfig") {
			continue
		}
		v, present := now[key]
		if w, had := was[key]; had == present && bytes.Equal(w, v) {
			continue
		}
		if present {
			top[key] = topEdit{value: v}
		} else {
			top[key] = topEdit{remove: true}
		}
	}
	return true
}

func rawValues(b []byte, obj rawSpan) (map[string][]byte, bool) {
	fields, err := rawFields(b, obj)
	if err != nil {
		return nil, false
	}
	out := make(map[string][]byte, len(fields))
	for _, f := range fields {
		out[f.key] = b[f.value.start:f.value.end]
	}
	return out, true
}

func (g *grafter) toolEntryPatches(origArr rawSpan, origItems []rawSpan, origTools []rawTool, encArr rawSpan) ([]rawPatch, bool) {
	encItems, encTools, ok := rawToolEntries(g.encoded, encArr)
	if !ok {
		return nil, false
	}
	origByName, ok := toolsByName(origTools)
	if !ok {
		return nil, false
	}
	encByName, ok := toolsByName(encTools)
	if !ok {
		return nil, false
	}
	before := map[string]CanonicalTool{}
	for _, t := range g.baseline.Tools {
		if _, dup := before[t.Name]; dup {
			return nil, false
		}
		if _, found := origByName[t.Name]; !found {
			return nil, false
		}
		before[t.Name] = t
	}
	after := map[string]CanonicalTool{}
	var added [][]byte
	lastKept := -1
	for _, t := range g.mutated.Tools {
		if _, dup := after[t.Name]; dup {
			return nil, false
		}
		after[t.Name] = t
		enc, found := encByName[t.Name]
		if !found {
			return nil, false
		}
		if _, existed := before[t.Name]; !existed {
			added = append(added, rawToolBytes(g.encoded, encItems, enc)...)
			continue
		}
		if len(added) > 0 || origByName[t.Name].item < lastKept {
			return nil, false
		}
		lastKept = origByName[t.Name].item
	}
	drop := make([]bool, len(origItems))
	replace := map[int][]byte{}
	for _, rt := range origTools {
		if rt.unmodelled {
			drop[rt.item] = !g.keepUnmodelled(rt.kind)
			continue
		}
		was := before[rt.name]
		now, kept := after[rt.name]
		if kept && bytes.Equal(toolsJSON([]CanonicalTool{was}), toolsJSON([]CanonicalTool{now})) {
			continue
		}
		for _, tr := range rt.trailers {
			drop[tr] = true
		}
		if !kept {
			drop[rt.item] = true
			continue
		}
		replace[rt.item] = bytes.Join(rawToolBytes(g.encoded, encItems, encByName[rt.name]), []byte(","))
	}
	return rawListEdits(origItems, origArr.end-1, drop, replace, added), true
}

// rawToolEntries reads the entries of a tools array. A Bedrock cachePoint
// entry belongs to the tool before it; one with no tool before it is left
// alone.
func rawToolEntries(b []byte, arr rawSpan) ([]rawSpan, []rawTool, bool) {
	items, err := rawItems(b, arr)
	if err != nil {
		return nil, nil, false
	}
	var tools []rawTool
	for i, item := range items {
		if b[item.start] != '{' {
			tools = append(tools, rawTool{item: i})
			continue
		}
		fields, err := rawFields(b, item)
		if err != nil {
			return nil, nil, false
		}
		if len(fields) == 1 && fields[0].key == "cachePoint" {
			if len(tools) > 0 {
				tools[len(tools)-1].trailers = append(tools[len(tools)-1].trailers, i)
			}
			continue
		}
		tools = append(tools, rawTool{name: rawToolName(b, item), item: i})
	}
	return items, tools, true
}

// keepUnmodelled applies GraftOptions.KeepUnmodelledTool to a tools entry
// the canonical request does not carry. With no option the entry goes: a
// filter that cannot see a tool must not let it through.
func (g *grafter) keepUnmodelled(kind string) bool {
	return g.opts.KeepUnmodelledTool != nil && g.opts.KeepUnmodelledTool(kind)
}

func rawToolKind(b []byte, item rawSpan) string {
	if b[item.start] != '{' {
		return ""
	}
	fields, err := rawFields(b, item)
	if err != nil {
		return ""
	}
	for _, f := range fields {
		if f.key == "type" {
			kind, _ := rawString(b, f.value)
			return kind
		}
	}
	if len(fields) == 1 {
		return fields[0].key
	}
	return ""
}

func rawToolName(b []byte, item rawSpan) string {
	for _, path := range [][]string{{"name"}, {"function", "name"}, {"custom", "name"}, {"toolSpec", "name"}} {
		if s, ok := rawAt(b, item, path); ok {
			if name, ok := rawString(b, s); ok && name != "" {
				return name
			}
		}
	}
	return ""
}

func toolsByName(tools []rawTool) (map[string]rawTool, bool) {
	out := make(map[string]rawTool, len(tools))
	for _, t := range tools {
		if t.name == "" {
			continue
		}
		if _, dup := out[t.name]; dup {
			return nil, false
		}
		out[t.name] = t
	}
	return out, true
}

func rawToolBytes(b []byte, items []rawSpan, t rawTool) [][]byte {
	out := [][]byte{b[items[t.item].start:items[t.item].end]}
	for _, tr := range t.trailers {
		out = append(out, b[items[tr].start:items[tr].end])
	}
	return out
}
