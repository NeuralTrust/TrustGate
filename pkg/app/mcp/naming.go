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

package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

func resolveNames(candidates []binding) []binding {
	items := make([]exposedName, len(candidates))
	for i, b := range candidates {
		items[i] = exposedName{name: b.exposed, registry: b.registry.Name, registryID: b.registry.ID.String()}
	}
	out := make([]binding, 0, len(candidates))
	for i, name := range resolveExposedNames(items) {
		b := candidates[i]
		b.exposed = name
		out = append(out, b)
	}
	return out
}

type exposedName struct {
	name       string
	registry   string
	registryID string
}

func resolveExposedNames(items []exposedName) []string {
	counts := make(map[string]int, len(items))
	for _, it := range items {
		counts[it.name]++
	}
	taken := make(map[string]struct{}, len(items))
	out := make([]string, len(items))
	for i, it := range items {
		name := it.name
		if counts[name] > 1 {
			name = registryPrefix(it) + "_" + it.name
		}
		if _, dup := taken[name]; dup {
			name = registryPrefix(it) + "_" + shortID(it.registryID) + "_" + it.name
		}
		base := name
		for n := 2; ; n++ {
			if _, dup := taken[name]; !dup {
				break
			}
			name = fmt.Sprintf("%s_%d", base, n)
		}
		taken[name] = struct{}{}
		out[i] = name
	}
	return out
}

var invalidNameChars = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeName(s string) string {
	s = invalidNameChars.ReplaceAllString(strings.TrimSpace(s), "_")
	return strings.Trim(s, "_")
}

func registryPrefix(it exposedName) string {
	if p := sanitizeName(it.registry); p != "" {
		return p
	}
	return "reg_" + shortID(it.registryID)
}

func shortID(id string) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
