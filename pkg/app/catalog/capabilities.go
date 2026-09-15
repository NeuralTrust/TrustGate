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

package catalog

import (
	"regexp"
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

// How many "What you can do" lines GET /v1/mcp-servers-catalog returns
// (Employee Portal side panel).
const capabilityCount = 3

const capabilityMaxLen = 72

var genericCapabilities = []string{
	"Search and read content",
	"Create and update records",
	"Actions logged by your organization",
}

var (
	skipTool = regexp.MustCompile(`(?i)^(ping|health|echo|noop|whoami)\b`)
	skipDesc = regexp.MustCompile(`(?i)\bping the mcp\b`)
)

// catalogCapabilities prefers seeded Portal copy, then tool descriptions, then
// the generic Figma fallback so every catalog server exposes capabilities.
func catalogCapabilities(seeded []string, tools []domain.MCPTool) []string {
	out := make([]string, 0, capabilityCount)
	seen := make(map[string]struct{}, capabilityCount)
	add := func(text string) bool {
		text = formatCapabilityLine(text)
		if text == "" {
			return false
		}
		key := strings.ToLower(text)
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
		out = append(out, text)
		return len(out) == capabilityCount
	}
	for _, line := range seeded {
		if add(line) {
			return out
		}
	}
	for _, tool := range tools {
		if skipTool.MatchString(tool.Name) || skipTool.MatchString(tool.Description) || skipDesc.MatchString(tool.Description) {
			continue
		}
		text := formatCapabilityLine(tool.Description)
		if text == "" || len(text) > capabilityMaxLen {
			text = humanizeToolName(tool.Name)
		}
		if add(text) {
			return out
		}
	}
	for _, fallback := range genericCapabilities {
		if add(fallback) {
			return out
		}
	}
	return out
}

func formatCapabilityLine(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if i := strings.IndexAny(text, ".!?"); i >= 0 && i < len(text)-1 {
		text = strings.TrimSpace(text[:i])
	}
	text = strings.TrimRight(text, ".:")
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) <= capabilityMaxLen {
		return text
	}
	cut := text[:capabilityMaxLen-1]
	if i := strings.LastIndex(cut, " "); i > 0 {
		cut = cut[:i]
	}
	return cut + "…"
}

func humanizeToolName(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.TrimSpace(name)
	lower := strings.ToLower(name)
	for _, prefix := range []string{"notion ", "github ", "figma ", "slack ", "jira ", "google ", "microsoft ", "aws "} {
		if strings.HasPrefix(lower, prefix) {
			name = strings.TrimSpace(name[len(prefix):])
			break
		}
	}
	if name == "" {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}
