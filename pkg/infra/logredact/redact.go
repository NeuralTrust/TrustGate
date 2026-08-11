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

package logredact

import (
	"regexp"
	"strings"
)

const placeholder = "[REDACTED]"

var (
	bearerPattern   = regexp.MustCompile(`(?i)\bbearer\s+\S+`)
	basicPattern    = regexp.MustCompile(`(?i)\bbasic\s+\S+`)
	headerPattern   = regexp.MustCompile(`(?i)\b(?:authorization|x-[\w-]*-api-key|api-key)\s*:\s*\S+`)
	jsonCredPattern = regexp.MustCompile(`(?i)"(?:api_key|apikey|token|secret|authorization|access_token|client_secret|private_key)"\s*:\s*"[^"]*"`)
	skKeyPattern    = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`)
	tgkKeyPattern   = regexp.MustCompile(`\btgk_[A-Za-z0-9_-]{8,}\b`)
)

// RedactLogString scrubs credential-shaped substrings from unstructured log text.
func RedactLogString(s string) string {
	if s == "" {
		return s
	}
	out := bearerPattern.ReplaceAllString(s, "Bearer "+placeholder)
	out = basicPattern.ReplaceAllString(out, "Basic "+placeholder)
	out = headerPattern.ReplaceAllStringFunc(out, func(match string) string {
		if idx := strings.Index(match, ":"); idx >= 0 {
			return match[:idx+1] + " " + placeholder
		}
		return placeholder
	})
	out = jsonCredPattern.ReplaceAllStringFunc(out, func(match string) string {
		if idx := strings.Index(match, ":"); idx >= 0 {
			key := strings.TrimSpace(match[:idx+1])
			return key + " \"" + placeholder + "\""
		}
		return match
	})
	out = skKeyPattern.ReplaceAllString(out, placeholder)
	out = tgkKeyPattern.ReplaceAllString(out, placeholder)
	return out
}
