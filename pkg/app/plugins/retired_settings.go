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

package plugins

import (
	"maps"
	"strings"
)

// RetiredSettings is the opt-in of a plugin that ignores some settings keys and
// must never store them. A stored key the plugin ignores still reads as
// behaviour to every consumer that does not know better (the policy API, the
// Terraform provider, a binary of another release), so the write path drops it
// instead of letting it round-trip.
//
// Paths are dot-separated and walk nested objects ("streaming.on_error" reaches
// settings["streaming"]["on_error"]). The declaration lives with the plugin that
// owns the shape, tied to that plugin's own key names.
type RetiredSettings interface {
	RetiredSettings() []string
}

// StripRetiredSettings returns settings without the keys slug declared as
// retired. Keys are matched case-insensitively at every level, because settings
// are decoded with mapstructure, which matches key names that way: an "On_Error"
// is as live on a decoder as "on_error".
//
// The input is never modified: a block is copied before the first key goes, and
// settings with nothing to drop are returned as they are. A nil registry, an
// unregistered slug or a plugin that declares none leaves settings untouched.
func StripRetiredSettings(reg Registry, slug string, settings map[string]any) map[string]any {
	if reg == nil || len(settings) == 0 {
		return settings
	}
	p, ok := reg.Get(slug)
	if !ok {
		return settings
	}
	r, ok := p.(RetiredSettings)
	if !ok {
		return settings
	}
	return stripPaths(settings, r.RetiredSettings())
}

func stripPaths(settings map[string]any, paths []string) map[string]any {
	out := settings
	for _, path := range paths {
		out, _ = dropPath(out, strings.Split(path, "."))
	}
	return out
}

// dropPath removes the key at parts from block. It reports whether anything
// went, and returns block itself, uncopied, when nothing did.
func dropPath(block map[string]any, parts []string) (map[string]any, bool) {
	head, rest := parts[0], parts[1:]
	var out map[string]any
	for key, val := range block {
		if !strings.EqualFold(key, head) {
			continue
		}
		if len(rest) == 0 {
			if out == nil {
				out = maps.Clone(block)
			}
			delete(out, key)
			continue
		}
		child, isObject := val.(map[string]any)
		if !isObject {
			continue
		}
		cleaned, changed := dropPath(child, rest)
		if !changed {
			continue
		}
		if out == nil {
			out = maps.Clone(block)
		}
		out[key] = cleaned
	}
	if out == nil {
		return block, false
	}
	return out, true
}
