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

import "strings"

// choicePatches edits the tool choices of original the adapter does not
// decode, which the upstream refuses once they name a tool the request no
// longer declares. A Responses tool_choice for a removed tool falls back to
// auto and its allowed_tools list keeps only the tools that stay, falling
// back to auto when none does. A Gemini allowedFunctionNames list drops the
// removed names; once none is left the list goes and the mode relaxes to
// AUTO, as does a forced mode once no function declaration stays.
func (g *grafter) choicePatches(root rawSpan, top map[string]topEdit) ([]rawPatch, bool) {
	switch g.ad.(type) {
	case *OpenAIResponsesAdapter:
		return g.responsesChoicePatches(root, top)
	case *GeminiAdapter:
		return g.geminiChoicePatches(root)
	}
	return nil, true
}

// stays reports whether a Responses tools entry of this kind and name is
// still declared: a function or custom tool by its name in mutated, any
// other kind by a built-in entry of that kind KeepUnmodelledTool keeps.
func (g *grafter) stays(kind, name string) bool {
	if kind == "function" || kind == "custom" {
		for _, t := range g.mutated.Tools {
			if t.Name == name && name != "" {
				return true
			}
		}
		return false
	}
	orig, _, ok := g.originalTools()
	if !ok {
		return false
	}
	for _, rt := range orig.tools {
		if rt.unmodelled && rt.kind == kind && g.keepUnmodelled(rt) {
			return true
		}
	}
	return false
}

func (g *grafter) responsesChoicePatches(root rawSpan, top map[string]topEdit) ([]rawPatch, bool) {
	b := g.original
	choice, found, ok := rawLookup(b, root, []string{"tool_choice"})
	if !ok {
		return nil, false
	}
	if !found || b[choice.start] != '{' {
		return nil, true
	}
	fields, err := rawFields(b, choice)
	if err != nil {
		return nil, false
	}
	auto := topEdit{value: []byte(`"auto"`)}
	kind := rawToolKind(b, fields)
	if kind != "allowed_tools" {
		if !g.stays(kind, rawToolName(b, fields)) {
			top["tool_choice"] = auto
		}
		return nil, true
	}
	list, found, ok := rawLookup(b, choice, []string{"tools"})
	if !ok {
		return nil, false
	}
	if !found || b[list.start] != '[' {
		return nil, true
	}
	items, err := rawItems(b, list)
	if err != nil {
		return nil, false
	}
	drop := make([]bool, len(items))
	dropped, kept := false, false
	for i, item := range items {
		stays := false
		if b[item.start] == '{' {
			entry, err := rawFields(b, item)
			if err != nil {
				return nil, false
			}
			stays = g.stays(rawToolKind(b, entry), rawToolName(b, entry))
		}
		drop[i] = !stays
		dropped = dropped || !stays
		kept = kept || stays
	}
	switch {
	case !kept:
		top["tool_choice"] = auto
		return nil, true
	case dropped:
		return rawListEdits(items, list.end-1, drop, nil, nil), true
	}
	return nil, true
}

func (g *grafter) geminiChoicePatches(root rawSpan) ([]rawPatch, bool) {
	b := g.original
	cfg, found, ok := rawFieldAlias(b, root, "toolConfig", "tool_config")
	if !ok || !found {
		return nil, ok
	}
	calling, found, ok := rawFieldAlias(b, cfg.value, "functionCallingConfig", "function_calling_config")
	if !ok || !found {
		return nil, ok
	}
	names, found, ok := rawFieldAlias(b, calling.value, "allowedFunctionNames", "allowed_function_names")
	if !ok {
		return nil, false
	}
	if !found || b[names.value.start] != '[' {
		return g.geminiForcedModePatches(calling.value)
	}
	items, err := rawItems(b, names.value)
	if err != nil {
		return nil, false
	}
	drop := make([]bool, len(items))
	dropped, kept := false, false
	for i, item := range items {
		name, _ := rawString(b, item)
		stays := g.stays("function", name)
		drop[i] = !stays
		dropped = dropped || !stays
		kept = kept || stays
	}
	switch {
	case !kept:
		return rawObjectEdits(b, calling.value, map[string]topEdit{
			names.key: {remove: true},
			"mode":    {value: []byte(`"AUTO"`)},
		})
	case dropped:
		return rawListEdits(items, names.value.end-1, drop, nil, nil), true
	}
	return nil, true
}

// geminiForcedModePatches relaxes a mode that forces a function call, ANY
// or VALIDATED, to AUTO once no function declaration stays: Gemini refuses
// such a mode without one.
func (g *grafter) geminiForcedModePatches(calling rawSpan) ([]rawPatch, bool) {
	for _, t := range g.mutated.Tools {
		if t.Name != "" {
			return nil, true
		}
	}
	mode, found, ok := rawFieldAlias(g.original, calling, "mode")
	if !ok || !found {
		return nil, ok
	}
	switch v, _ := rawString(g.original, mode.value); strings.ToUpper(v) {
	case "ANY", "VALIDATED":
		return rawObjectEdits(g.original, calling, map[string]topEdit{mode.key: {value: []byte(`"AUTO"`)}})
	}
	return nil, true
}

// rawFieldAlias returns the field of the object at s whose key matches one
// of keys, as the decoder matches it. found is false when s is not an object
// or has no such field; ok is false when s cannot be read or two of its
// fields match.
func rawFieldAlias(b []byte, s rawSpan, keys ...string) (rawField, bool, bool) {
	if s.end-s.start < 2 || b[s.start] != '{' {
		return rawField{}, false, true
	}
	fields, err := rawFields(b, s)
	if err != nil {
		return rawField{}, false, false
	}
	return rawFieldNamed(fields, keys...)
}
