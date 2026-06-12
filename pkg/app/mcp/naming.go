package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

func resolveNames(candidates []binding) []binding {
	items := make([]exposedName, len(candidates))
	for i, b := range candidates {
		items[i] = exposedName{name: b.exposed, registry: b.registry.Name}
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
	name     string
	registry string
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
			name = sanitizeName(it.registry) + "_" + it.name
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
