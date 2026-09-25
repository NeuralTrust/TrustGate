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
	name     string
	item     int
	trailers []int
}

// toolPatches edits the tools array of original entry by entry: unchanged
// tools keep their bytes, changed ones take their re-encoded form, removed
// ones go and new ones are appended. Tools the canonical model does not
// carry stay where they are. Top-level keys the tool change touched in the
// re-encode (a tool_choice that named a removed tool) are recorded in top.
// When the entries cannot be matched by name, the whole tools value is
// replaced by the re-encoded one.
func (g *grafter) toolPatches(root rawSpan, top map[string]topEdit) ([]rawPatch, bool) {
	encRoot, err := rawRoot(g.encoded)
	if err != nil {
		return nil, false
	}
	if !g.otherTopEdits(encRoot, top) {
		return nil, false
	}
	topKey, path := "tools", []string{"tools"}
	if _, ok := rawFieldOf(g.original, root, "toolConfig"); ok {
		topKey, path = "toolConfig", []string{"toolConfig", "tools"}
	} else if _, ok := rawFieldOf(g.encoded, encRoot, "toolConfig"); ok {
		topKey, path = "toolConfig", []string{"toolConfig", "tools"}
	}
	origArr, hasOrig := rawAt(g.original, root, path)
	encArr, hasEnc := rawAt(g.encoded, encRoot, path)
	if !hasOrig || !hasEnc || len(g.mutated.Tools) == 0 {
		if v, ok := rawFieldOf(g.encoded, encRoot, topKey); ok {
			top[topKey] = topEdit{value: g.encoded[v.start:v.end]}
		} else {
			top[topKey] = topEdit{remove: true}
		}
		return nil, true
	}
	if patches, ok := g.toolEntryPatches(origArr, encArr); ok {
		return patches, true
	}
	return []rawPatch{{at: origArr, with: g.encoded[encArr.start:encArr.end]}}, true
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
		if graftedKeys[key] {
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

func (g *grafter) toolEntryPatches(origArr, encArr rawSpan) ([]rawPatch, bool) {
	origItems, origTools, ok := rawToolEntries(g.original, origArr)
	if !ok {
		return nil, false
	}
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
		was, modelled := before[rt.name]
		if rt.name == "" || !modelled {
			continue
		}
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
// entry belongs to the tool before it.
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
		if _, isCachePoint := rawFieldOf(b, item, "cachePoint"); isCachePoint && len(tools) > 0 {
			if _, isSpec := rawFieldOf(b, item, "toolSpec"); !isSpec {
				tools[len(tools)-1].trailers = append(tools[len(tools)-1].trailers, i)
				continue
			}
		}
		tools = append(tools, rawTool{name: rawToolName(b, item), item: i})
	}
	return items, tools, true
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
