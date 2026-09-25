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
	"reflect"
	"slices"
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

// DropDanglingToolChoice sets a tool choice that names a tool req no longer
// declares back to auto, so a filter that removed the tool does not leave a
// request the upstream refuses.
func DropDanglingToolChoice(req *CanonicalRequest) {
	if req == nil || req.ToolChoice == nil || req.ToolChoice.Name == "" {
		return
	}
	for _, t := range req.Tools {
		if t.Name == req.ToolChoice.Name {
			return
		}
	}
	req.ToolChoice = &CanonicalToolChoice{Type: "auto"}
}

// sameTools reports whether a and b encode alike. A schema both share, as a
// Clone shares it, is not compared again.
func sameTools(a, b []CanonicalTool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameTool(&a[i], &b[i]) {
			return false
		}
	}
	return true
}

func sameTool(a, b *CanonicalTool) bool {
	if a.Kind != b.Kind || a.Name != b.Name || a.Description != b.Description ||
		!sameRawJSON(a.Format, b.Format) || (a.Cache == nil) != (b.Cache == nil) ||
		(a.Cache != nil && a.Cache.TTL != b.Cache.TTL) || len(a.Schema) != len(b.Schema) {
		return false
	}
	if len(a.Schema) == 0 || reflect.ValueOf(a.Schema).UnsafePointer() == reflect.ValueOf(b.Schema).UnsafePointer() ||
		reflect.DeepEqual(a.Schema, b.Schema) {
		return true
	}
	x, errX := json.Marshal(a.Schema)
	y, errY := json.Marshal(b.Schema)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}

func sameRawJSON(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}

// UnmodelledTool is a tools entry the canonical request does not carry.
type UnmodelledTool struct {
	// Kind is the entry's "type", or its only key, or "" when it has neither:
	// a built-in or server tool such as mcp or web_search. A Bedrock system
	// tool is "systemTool:<name>", a Gemini tools object that mixes kinds
	// counts once per key, and the entries of Chat's legacy functions and
	// Anthropic's mcp_servers lists are "functions" and "mcp_servers".
	Kind string
	// Name is the entry's name, when it has one.
	Name string
}

type rawTool struct {
	name       string
	kind       string
	item       int
	part       *rawField
	trailers   []int
	unmodelled bool
}

func (t rawTool) unmodelledTool() UnmodelledTool {
	return UnmodelledTool{Kind: t.kind, Name: t.name}
}

// bytes returns the entry with its trailers, or the one key of a Gemini
// tools object it stands for as an object of its own.
func (t rawTool) bytes(b []byte, items []rawSpan) [][]byte {
	if t.part != nil {
		return [][]byte{append(append([]byte{'{'}, b[t.part.entry.start:t.part.entry.end]...), '}')}
	}
	return rawToolBytes(b, items, t)
}

type rawToolList struct {
	arr   rawSpan
	items []rawSpan
	tools []rawTool
}

// UnmodelledTools returns the tools entries of body that req, decoded from
// body by ad, does not carry. An entry sharing its name with more entries
// than req has tools of that name counts too, since which one req carries is
// unknown. ok is false when the tools cannot be read, as when an object on
// the way to them repeats a key.
func UnmodelledTools(ad RequestAdapter, body []byte, req *CanonicalRequest) ([]UnmodelledTool, bool) {
	if ad == nil || req == nil {
		return nil, false
	}
	root, err := rawRoot(body)
	if err != nil || body[root.start] != '{' {
		return nil, false
	}
	list, _, ok := rawToolsOf(ad, body, root, req.Tools)
	if !ok {
		return nil, false
	}
	extra, ok := rawExtraTools(ad, body, root)
	if !ok {
		return nil, false
	}
	var out []UnmodelledTool
	for _, t := range append(list.tools, extra.tools...) {
		if t.unmodelled {
			out = append(out, t.unmodelledTool())
		}
	}
	return out, true
}

// ServerToolTypes returns, by tool name, the "type" of each named Anthropic
// tools entry that is a server tool (web_search_20250305, bash_20250124):
// the adapter models those by their name alone. It is nil for other formats
// or when the tools cannot be read.
func ServerToolTypes(ad RequestAdapter, body []byte) map[string][]string {
	if _, ok := ad.(*AnthropicAdapter); !ok {
		return nil
	}
	root, err := rawRoot(body)
	if err != nil || body[root.start] != '{' {
		return nil
	}
	list, found, ok := rawToolsOf(ad, body, root, nil)
	if !found || !ok {
		return nil
	}
	var out map[string][]string
	for _, t := range list.tools {
		if t.name == "" || t.kind == "" || t.kind == "custom" {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[t.name] = append(out[t.name], t.kind)
	}
	return out
}

func toolsPath(ad RequestAdapter) (string, []string) {
	if _, bedrock := ad.(*BedrockAdapter); bedrock {
		return "toolConfig", []string{"toolConfig", "tools"}
	}
	return "tools", []string{"tools"}
}

// extraToolList returns the top-level key of the second tools list a format
// has and its adapter does not decode: Chat's legacy functions and
// Anthropic's MCP servers.
func extraToolList(ad RequestAdapter) string {
	switch ad.(type) {
	case *OpenAIAdapter, *MistralAdapter, *OpenRouterAdapter:
		return "functions"
	case *AnthropicAdapter:
		return "mcp_servers"
	}
	return ""
}

// rawToolsOf reads the tools array of the object at root and marks the
// entries modelled does not carry. found is false when there is no array.
func rawToolsOf(ad RequestAdapter, b []byte, root rawSpan, modelled []CanonicalTool) (rawToolList, bool, bool) {
	_, path := toolsPath(ad)
	arr, found, ok := rawLookup(b, root, path)
	if !ok {
		return rawToolList{}, false, false
	}
	if !found {
		return rawToolList{}, false, true
	}
	_, gemini := ad.(*GeminiAdapter)
	items, tools, ok := rawToolEntries(b, arr, gemini)
	if !ok {
		return rawToolList{}, true, false
	}
	if !gemini {
		markUnmodelled(tools, modelled)
	}
	return rawToolList{arr: arr, items: items, tools: tools}, true, true
}

func rawExtraTools(ad RequestAdapter, b []byte, root rawSpan) (rawToolList, bool) {
	key := extraToolList(ad)
	if key == "" {
		return rawToolList{}, true
	}
	arr, found, ok := rawLookup(b, root, []string{key})
	if !ok || !found {
		return rawToolList{}, ok
	}
	items, err := rawItems(b, arr)
	if err != nil {
		return rawToolList{}, false
	}
	tools := make([]rawTool, 0, len(items))
	for i, item := range items {
		t := rawTool{kind: key, item: i, unmodelled: true}
		if b[item.start] == '{' {
			fields, err := rawFields(b, item)
			if err != nil {
				return rawToolList{}, false
			}
			t.name = rawToolName(b, fields)
		}
		tools = append(tools, t)
	}
	return rawToolList{arr: arr, items: items, tools: tools}, true
}

func markUnmodelled(tools []rawTool, modelled []CanonicalTool) {
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
		t.unmodelled = t.name == "" || have[t.name] > want[t.name]
	}
}

func isGeminiDeclarations(key string) bool {
	return strings.EqualFold(key, "functionDeclarations") || strings.EqualFold(key, "function_declarations")
}

// geminiParts reads one Gemini tools object. The function declarations in it
// are what the adapter decodes; every other key is a tool of its own kind,
// so an object that mixes googleSearch with declarations is judged key by
// key.
func geminiParts(tools []rawTool, i int, fields []rawField) []rawTool {
	if len(fields) == 0 {
		return append(tools, rawTool{item: i, unmodelled: true})
	}
	decls := 0
	for _, f := range fields {
		if isGeminiDeclarations(f.key) {
			decls++
		}
	}
	if decls == len(fields) {
		return append(tools, rawTool{item: i})
	}
	for j := range fields {
		if !isGeminiDeclarations(fields[j].key) {
			tools = append(tools, rawTool{kind: fields[j].key, item: i, part: &fields[j], unmodelled: true})
		}
	}
	return tools
}

// refusesUnmodelledTool reports whether KeepUnmodelledTool refuses a tools
// entry of original the baseline does not carry, which must then go even
// though the modelled tools are unchanged. A body whose tools cannot be read
// counts as refused, so the full re-encode drops them.
func (g *grafter) refusesUnmodelledTool() bool {
	if g.opts.KeepUnmodelledTool == nil {
		return false
	}
	orig, _, ok := g.originalTools()
	if !ok {
		return true
	}
	extra, ok := g.originalExtraTools()
	if !ok {
		return true
	}
	for _, t := range append(orig.tools, extra.tools...) {
		if t.unmodelled && !g.keepUnmodelled(t) {
			return true
		}
	}
	return false
}

func (g *grafter) originalRoot() (rawSpan, bool) {
	root, err := rawRoot(g.original)
	return root, err == nil && g.original[root.start] == '{'
}

// originalTools reads the tools of original once for the grafter.
func (g *grafter) originalTools() (rawToolList, bool, bool) {
	if !g.origRead {
		g.origRead = true
		if root, ok := g.originalRoot(); ok {
			g.orig, g.origFound, g.origOK = rawToolsOf(g.ad, g.original, root, g.baseline.Tools)
		}
	}
	return g.orig, g.origFound, g.origOK
}

func (g *grafter) originalExtraTools() (rawToolList, bool) {
	root, ok := g.originalRoot()
	if !ok {
		return rawToolList{}, false
	}
	return rawExtraTools(g.ad, g.original, root)
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
	orig, hasOrig, ok := g.originalTools()
	if !ok {
		return nil, false
	}
	patches, ok := g.extraToolPatches(root, top)
	if !ok {
		return nil, false
	}
	var kept [][]byte
	for _, rt := range orig.tools {
		if rt.unmodelled && g.keepUnmodelled(rt) {
			kept = append(kept, rt.bytes(g.original, orig.items)...)
		}
	}
	topKey, path := toolsPath(g.ad)
	encArr, hasEnc, ok := rawLookup(g.encoded, encRoot, path)
	if !ok {
		return nil, false
	}
	if !hasOrig || !hasEnc || len(g.mutated.Tools) == 0 {
		switch v, ok := rawFieldOf(g.encoded, encRoot, topKey); {
		case len(kept) > 0 && hasOrig && !g.bedrock:
			top[topKey] = topEdit{value: joinRawArray(nil, kept)}
		case ok:
			top[topKey] = topEdit{value: g.encoded[v.start:v.end]}
		default:
			top[topKey] = topEdit{remove: true}
		}
		return patches, true
	}
	if p, ok := g.toolEntryPatches(orig, encArr); ok {
		return append(patches, p...), true
	}
	encItems, err := rawItems(g.encoded, encArr)
	if err != nil {
		return nil, false
	}
	whole := make([][]byte, 0, len(encItems)+len(kept))
	for _, it := range encItems {
		whole = append(whole, g.encoded[it.start:it.end])
	}
	return append(patches, rawPatch{at: orig.arr, with: joinRawArray(whole, kept)}), true
}

// extraToolPatches drops the entries of the second tools list (legacy
// functions, mcp_servers) that KeepUnmodelledTool refuses, and the whole key
// when none stays. A legacy function_call naming a dropped function goes with
// it. With no option the list is left alone.
func (g *grafter) extraToolPatches(root rawSpan, top map[string]topEdit) ([]rawPatch, bool) {
	if g.opts.KeepUnmodelledTool == nil {
		return nil, true
	}
	extra, ok := g.originalExtraTools()
	if !ok {
		return nil, false
	}
	drop := make([]bool, len(extra.items))
	dropped := map[string]bool{}
	for _, t := range extra.tools {
		if !g.keepUnmodelled(t) {
			drop[t.item] = true
			dropped[t.name] = true
		}
	}
	if len(dropped) == 0 {
		return nil, true
	}
	key := extraToolList(g.ad)
	if key == "functions" {
		call, found, _ := rawLookup(g.original, root, []string{"function_call"})
		if found && g.original[call.start] == '{' {
			name, named, ok := rawLookup(g.original, call, []string{"name"})
			if !ok || (named && dropped[rawStringOr(g.original, name)]) {
				top["function_call"] = topEdit{remove: true}
			}
		}
	}
	if !slices.Contains(drop, false) {
		top[key] = topEdit{remove: true}
		return nil, true
	}
	return rawListEdits(extra.items, extra.arr.end-1, drop, nil, nil), true
}

func rawStringOr(b []byte, s rawSpan) string {
	v, _ := rawString(b, s)
	return v
}

func joinRawArray(a, b [][]byte) []byte {
	return append(append([]byte{'['}, bytes.Join(append(a, b...), []byte(","))...), ']')
}

// toolShape is r without text, images or tool schemas: enough for the
// encoder to decide the top-level keys a tool edit can touch, such as a
// tool_choice that names a removed tool, at a fraction of the cost of
// encoding r.
func toolShape(r *CanonicalRequest) *CanonicalRequest {
	c := withoutTextAndTools(r)
	c.ToolChoice = r.ToolChoice
	for i := range c.Messages {
		c.Messages[i].Images = nil
	}
	c.Tools = make([]CanonicalTool, len(r.Tools))
	for i, t := range r.Tools {
		t.Description, t.Schema = "", nil
		c.Tools[i] = t
	}
	return c
}

// otherTopEdits records in top the top-level keys other than text and tools
// whose re-encoded value the tool edit changed. It compares encodings of the
// requests' shape and takes the value from the full re-encode; when a shape
// does not encode, it compares the full encodings.
func (g *grafter) otherTopEdits(encRoot rawSpan, top map[string]topEdit) bool {
	before, errBefore := g.ad.EncodeRequest(toolShape(g.baseline))
	after, errAfter := g.ad.EncodeRequest(toolShape(g.mutated))
	if errBefore != nil || errAfter != nil {
		var err error
		if before, err = g.ad.EncodeRequest(g.baseline); err != nil {
			return false
		}
		after = g.encoded
	}
	was, ok := rawTopValues(before)
	if !ok {
		return false
	}
	now, ok := rawTopValues(after)
	if !ok {
		return false
	}
	full, ok := rawValues(g.encoded, encRoot)
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
		if !present {
			top[key] = topEdit{remove: true}
			continue
		}
		value, inFull := full[key]
		if !inFull {
			return false
		}
		top[key] = topEdit{value: value}
	}
	return true
}

func rawTopValues(b []byte) (map[string][]byte, bool) {
	root, err := rawRoot(b)
	if err != nil {
		return nil, false
	}
	return rawValues(b, root)
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

func (g *grafter) toolEntryPatches(orig rawToolList, encArr rawSpan) ([]rawPatch, bool) {
	origItems, origTools := orig.items, orig.tools
	for _, rt := range origTools {
		if rt.part != nil {
			return nil, false
		}
	}
	_, gemini := g.ad.(*GeminiAdapter)
	encItems, encTools, ok := rawToolEntries(g.encoded, encArr, gemini)
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
	before := map[string]*CanonicalTool{}
	for i := range g.baseline.Tools {
		t := &g.baseline.Tools[i]
		if _, dup := before[t.Name]; dup {
			return nil, false
		}
		if _, found := origByName[t.Name]; !found {
			return nil, false
		}
		before[t.Name] = t
	}
	after := map[string]*CanonicalTool{}
	var added [][]byte
	lastKept := -1
	for i := range g.mutated.Tools {
		t := &g.mutated.Tools[i]
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
			drop[rt.item] = !g.keepUnmodelled(rt)
			continue
		}
		was := before[rt.name]
		now, kept := after[rt.name]
		if kept && sameTool(was, now) {
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
	return rawListEdits(origItems, orig.arr.end-1, drop, replace, added), true
}

// rawToolEntries reads the entries of a tools array, reading each entry's
// keys once. A Bedrock cachePoint entry belongs to the tool before it; one
// with no tool before it is left alone. Gemini tools objects are read by
// geminiParts.
func rawToolEntries(b []byte, arr rawSpan, gemini bool) ([]rawSpan, []rawTool, bool) {
	items, err := rawItems(b, arr)
	if err != nil {
		return nil, nil, false
	}
	tools := make([]rawTool, 0, len(items))
	for i, item := range items {
		if b[item.start] != '{' {
			tools = append(tools, rawTool{item: i, unmodelled: gemini})
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
		if gemini {
			tools = geminiParts(tools, i, fields)
			continue
		}
		tools = append(tools, rawTool{name: rawToolName(b, fields), kind: rawToolKind(b, fields), item: i})
	}
	return items, tools, true
}

// keepUnmodelled applies GraftOptions.KeepUnmodelledTool to a tools entry
// the canonical request does not carry. With no option the entry goes: a
// filter that cannot see a tool must not let it through.
func (g *grafter) keepUnmodelled(t rawTool) bool {
	return g.opts.KeepUnmodelledTool != nil && g.opts.KeepUnmodelledTool(t.unmodelledTool())
}

// rawToolKind returns the entry's "type", matched as the decoder matches it,
// or its only key. A Bedrock system tool is "systemTool:<name>".
func rawToolKind(b []byte, fields []rawField) string {
	for _, f := range fields {
		if strings.EqualFold(f.key, "type") {
			kind, _ := rawString(b, f.value)
			return kind
		}
	}
	if len(fields) != 1 {
		return ""
	}
	if fields[0].key == "systemTool" {
		if s, ok := rawAt(b, fields[0].value, []string{"name"}); ok {
			if name, ok := rawString(b, s); ok && name != "" {
				return "systemTool:" + name
			}
		}
	}
	return fields[0].key
}

func rawToolName(b []byte, fields []rawField) string {
	for _, key := range []string{"name", "function", "custom", "toolSpec"} {
		for _, f := range fields {
			if !strings.EqualFold(f.key, key) {
				continue
			}
			s := f.value
			if key != "name" {
				var ok bool
				if s, ok = rawAt(b, f.value, []string{"name"}); !ok {
					break
				}
			}
			if name, ok := rawString(b, s); ok && name != "" {
				return name
			}
			break
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
