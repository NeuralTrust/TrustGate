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
	"encoding/json"
	"strings"
	"unicode/utf8"

	segmentjson "github.com/segmentio/encoding/json"
)

// List metadata has no content body, so 64 KiB accommodates bounded declarations without permitting document-sized scans.
const maxAppsListMetadataBytes = 64 * 1024

type appsMetadataScan uint8

const (
	appsMetadataUnrelated appsMetadataScan = iota
	appsMetadataMarked
	appsMetadataInvalid
)

// AppsListOutcome reports bounded metadata about Apps list filtering.
type AppsListOutcome struct {
	Dropped int
}

// AppsListPolicy filters invalid Apps declarations from MCP list results.
type AppsListPolicy struct {
	enabled  bool
	metadata AppsMetadataPolicy
}

// NewAppsListPolicy builds an immutable Apps list policy.
func NewAppsListPolicy(enabled bool, metadata AppsMetadataPolicy) AppsListPolicy {
	return AppsListPolicy{enabled: enabled, metadata: metadata}
}

// Enabled reports whether Apps list enforcement is active.
func (p AppsListPolicy) Enabled() bool {
	return p.enabled
}

// FilterTools removes tools with invalid marked Apps metadata.
func (p AppsListPolicy) FilterTools(tools []Tool) ([]Tool, AppsListOutcome) {
	return filterAppsList(p.enabled, tools, validToolAppsMetadata)
}

// FilterResources removes resources with invalid marked Apps metadata.
func (p AppsListPolicy) FilterResources(resources []Resource) ([]Resource, AppsListOutcome) {
	return filterAppsList(p.enabled, resources, p.validResource)
}

// FilterResourceTemplates removes templates carrying Apps-only metadata markers.
func (p AppsListPolicy) FilterResourceTemplates(templates []ResourceTemplate) ([]ResourceTemplate, AppsListOutcome) {
	return filterAppsList(p.enabled, templates, func(template ResourceTemplate) bool {
		_, marked := markedAppsMetadata(template.payload["_meta"], appsMetadataMarker)
		return !marked
	})
}

// FilterToolsWithResources removes Apps tools whose validated resource is absent from the same upstream surface.
func (p AppsListPolicy) FilterToolsWithResources(tools []Tool, resources []Resource) ([]Tool, AppsListOutcome) {
	if !p.enabled {
		return tools, AppsListOutcome{}
	}
	validResources := make(map[string]bool, len(resources))
	for _, resource := range resources {
		if p.validResource(resource) {
			validResources[resource.source+"\x00"+resource.URI] = true
		}
	}
	return filterAppsList(true, tools, func(tool Tool) bool {
		metadata, marked, err := toolAppsMetadata(tool)
		return !marked || err == nil && metadata.ResourceURI != "" &&
			validResources[tool.source+"\x00"+metadata.ResourceURI]
	})
}

// HasToolResourceReferences reports whether validated tools require resource binding.
func (p AppsListPolicy) HasToolResourceReferences(tools []Tool) bool {
	if !p.enabled {
		return false
	}
	for _, tool := range tools {
		metadata, marked, err := toolAppsMetadata(tool)
		if marked && err == nil && metadata.ResourceURI != "" {
			return true
		}
	}
	return false
}

// ValidateReadBinding rejects unbound or cross-upstream ambiguous Apps reads.
func (p AppsListPolicy) ValidateReadBinding(uri string, resources []Resource) error {
	if !p.enabled {
		return nil
	}
	found, source := false, ""
	for _, resource := range resources {
		if resource.URI != uri || !p.validResource(resource) {
			continue
		}
		if found && source != resource.source {
			return ErrAppsResourceRejected
		}
		found, source = true, resource.source
	}
	if !found {
		return ErrAppsResourceRejected
	}
	return nil
}

func filterAppsList[T any](enabled bool, values []T, valid func(T) bool) ([]T, AppsListOutcome) {
	if !enabled {
		return values, AppsListOutcome{}
	}
	var filtered []T
	outcome := AppsListOutcome{}
	for i, value := range values {
		if valid(value) {
			if filtered != nil {
				filtered = append(filtered, value)
			}
			continue
		}
		if filtered == nil {
			filtered = make([]T, 0, len(values)-1)
			filtered = append(filtered, values[:i]...)
		}
		outcome.Dropped++
	}
	if filtered == nil {
		return values, outcome
	}
	return filtered, outcome
}

func validToolAppsMetadata(tool Tool) bool {
	metadata, marked, err := toolAppsMetadata(tool)
	if !marked {
		return true
	}
	return err == nil && metadata.ResourceURI != ""
}

func toolAppsMetadata(tool Tool) (ToolAppsMetadata, bool, error) {
	meta, marked := markedAppsMetadata(tool.payload["_meta"], appsMetadataMarker)
	if !marked {
		return ToolAppsMetadata{}, false, nil
	}
	if meta == nil {
		return ToolAppsMetadata{}, true, ErrInvalidAppsMetadata
	}
	parsed, err := ParseToolAppsMetadata(meta)
	return parsed, true, err
}

func (p AppsListPolicy) validResource(resource Resource) bool {
	meta, marked := markedAppsMetadata(resource.payload["_meta"], appsMetadataMarker)
	if !marked {
		return true
	}
	if meta == nil {
		return false
	}
	if _, err := ValidateAppsURI(resource.URI); err != nil {
		return false
	}
	return ValidateResourceAppsMetadata(meta["ui"], p.metadata) == nil
}

func appsMetadataMarker(key string) bool {
	return key == "ui" || strings.HasPrefix(key, "ui/")
}

func markedAppsMetadata(raw json.RawMessage, marker func(string) bool) (map[string]any, bool) {
	switch hasAppsMetadataMarker(raw, marker) {
	case appsMetadataUnrelated:
		return nil, false
	case appsMetadataInvalid:
		return nil, true
	}
	if validateAppsJSON(raw) != nil {
		return nil, true
	}
	var meta map[string]any
	if json.Unmarshal(raw, &meta) != nil {
		return nil, true
	}
	return meta, true
}

func hasAppsMetadataMarker(raw json.RawMessage, marker func(string) bool) appsMetadataScan {
	first, present := firstAppsMetadataByte(raw)
	if !present {
		if len(raw) > maxAppsListMetadataBytes {
			return appsMetadataInvalid
		}
		return appsMetadataUnrelated
	}
	if first != '{' {
		return appsMetadataUnrelated
	}
	if len(raw) > maxAppsListMetadataBytes || !utf8.Valid(raw) {
		return appsMetadataInvalid
	}
	tokenizer := segmentjson.NewTokenizer(raw)
	stack := make([]segmentjson.Delim, 0, maxAppsJSONDepth)
	marked := false
	closed := false
	tokens := 0
	for tokenizer.Next() {
		tokens++
		if tokens > maxAppsJSONTokens || closed {
			return appsMetadataInvalid
		}
		switch tokenizer.Delim {
		case '{', '[':
			if len(stack) >= maxAppsJSONDepth || len(stack) == 0 && tokenizer.Delim != '{' {
				return appsMetadataInvalid
			}
			stack = append(stack, tokenizer.Delim)
		case '}', ']':
			if len(stack) == 0 || tokenizer.Delim == '}' && stack[len(stack)-1] != '{' ||
				tokenizer.Delim == ']' && stack[len(stack)-1] != '[' {
				return appsMetadataInvalid
			}
			stack = stack[:len(stack)-1]
			closed = len(stack) == 0
		default:
			if len(stack) == 0 {
				return appsMetadataInvalid
			}
			if len(stack) == 1 && tokenizer.IsKey && marker(string(tokenizer.String())) {
				marked = true
			}
		}
	}
	if tokenizer.Err != nil || len(stack) != 0 || !closed {
		return appsMetadataInvalid
	}
	if marked {
		return appsMetadataMarked
	}
	return appsMetadataUnrelated
}

func firstAppsMetadataByte(raw json.RawMessage) (byte, bool) {
	limit := len(raw)
	if limit > maxAppsListMetadataBytes+1 {
		limit = maxAppsListMetadataBytes + 1
	}
	for _, value := range raw[:limit] {
		switch value {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return value, true
		}
	}
	return 0, false
}
