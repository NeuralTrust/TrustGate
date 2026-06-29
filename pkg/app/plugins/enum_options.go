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
	"strings"
	"unicode"
)

// enumLabelOverrides maps raw enum values whose pretty label cannot be derived
// mechanically to the exact label shown in the admin UI.
var enumLabelOverrides = map[string]string{
	"request_response": "Request & Response",
	"in_memory":        "In-Memory",
	"pre_request":      "Pre-Request",
	"pre_response":     "Pre-Response",
	"pgvector":         "pgvector",
	"SelfHarm":         "Self-Harm",
}

// enumLabelAcronyms maps lowercased word tokens to their canonical casing so
// labels read naturally (e.g. "json" -> "JSON").
var enumLabelAcronyms = map[string]string{
	"openai": "OpenAI",
	"json":   "JSON",
	"jwt":    "JWT",
	"http":   "HTTP",
	"url":    "URL",
	"api":    "API",
	"id":     "ID",
	"pii":    "PII",
	"ttl":    "TTL",
}

// enumOptions pairs each raw enum value with a human-readable label for the
// admin UI. The value sent back to the API stays the raw enum string.
func enumOptions(values ...string) []EnumOption {
	options := make([]EnumOption, len(values))
	for i, value := range values {
		options[i] = EnumOption{Value: value, Label: humanizeEnumLabel(value)}
	}
	return options
}

func humanizeEnumLabel(value string) string {
	if label, ok := enumLabelOverrides[value]; ok {
		return label
	}
	words := splitEnumWords(value)
	for i, word := range words {
		if isAllUpper(word) {
			continue
		}
		lower := strings.ToLower(word)
		if acronym, ok := enumLabelAcronyms[lower]; ok {
			words[i] = acronym
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

// splitEnumWords breaks an enum value into words on underscores and camelCase
// boundaries, keeping all-uppercase tokens (e.g. HTTP methods) intact.
func splitEnumWords(value string) []string {
	words := make([]string, 0, 4)
	for _, part := range strings.Split(value, "_") {
		if part == "" {
			continue
		}
		words = append(words, splitCamelCase(part)...)
	}
	return words
}

func splitCamelCase(part string) []string {
	if isAllUpper(part) {
		return []string{part}
	}
	var words []string
	var current strings.Builder
	for i, r := range part {
		if i > 0 && unicode.IsUpper(r) && !unicode.IsUpper(rune(part[i-1])) {
			words = append(words, current.String())
			current.Reset()
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words
}

func isAllUpper(s string) bool {
	hasLetter := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			hasLetter = true
			if !unicode.IsUpper(r) {
				return false
			}
		}
	}
	return hasLetter
}
