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

package promptcompression

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// ansiEscape matches ANSI CSI/OSC escape sequences (colors, cursor movement)
// that captured terminal output and CI logs carry but models never need.
var ansiEscape = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)

// fencedJSONBlock matches ```json ... ``` fenced blocks so JSON embedded in
// prose (typical of tool outputs pasted into messages) can be compacted
// without touching the surrounding text.
var fencedJSONBlock = regexp.MustCompile("(?s)```json[ \t]*\\n(.*?)\\n[ \t]*```")

// compressContent applies the configured transforms to a single message body
// and reports whether anything changed. Transforms are ordered so structural
// work (JSON) happens before textual cleanup, and every step is deterministic.
func compressContent(content string, cfg Settings) (string, bool) {
	if len(content) < cfg.MinLength {
		return content, false
	}
	out := content
	if cfg.StripANSI && strings.Contains(out, "\x1b") {
		out = ansiEscape.ReplaceAllString(out, "")
	}
	if cfg.CompressJSON {
		// Route on the first byte only; compactJSON validates via json.Compact's
		// own error return, so standalone JSON is scanned exactly once.
		if trimmed := strings.TrimSpace(out); len(trimmed) >= 2 && (trimmed[0] == '{' || trimmed[0] == '[') {
			out = compactJSON(out)
		} else {
			out = compactFencedJSON(out)
		}
	}
	if cfg.NormalizeWhitespace {
		out = normalizeWhitespace(out, cfg.MaxConsecutiveBlankLines)
	}
	return out, out != content
}

// compactJSON minifies a standalone JSON document. It is byte-lossless with
// respect to the decoded value: only inter-token whitespace is removed. On any
// failure (including invalid JSON) the original text is returned untouched.
func compactJSON(content string) string {
	trimmed := strings.TrimSpace(content)
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(trimmed)); err != nil {
		return content
	}
	if buf.Len() >= len(content) {
		return content
	}
	return buf.String()
}

// compactFencedJSON minifies every valid ```json fenced block inside prose,
// leaving the fences and all surrounding text byte-identical.
func compactFencedJSON(content string) string {
	if !strings.Contains(content, "```json") {
		return content
	}
	return fencedJSONBlock.ReplaceAllStringFunc(content, func(block string) string {
		m := fencedJSONBlock.FindStringSubmatch(block)
		if m == nil {
			return block
		}
		inner := m[1]
		compacted := compactJSON(inner)
		if compacted == inner {
			return block
		}
		return "```json\n" + compacted + "\n```"
	})
}

// normalizeWhitespace trims trailing spaces and tabs from every line and caps
// runs of blank lines at maxBlank. Two exceptions keep the transform safe for
// formatted text: leading whitespace (indentation) is preserved because it can
// be semantically meaningful (code, YAML, Markdown), and lines ending in two
// or more spaces keep exactly two so Markdown hard line breaks survive.
func normalizeWhitespace(content string, maxBlank int) string {
	if !mayNeedNormalization(content, maxBlank) {
		return content
	}
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	blanks := 0
	changed := false
	for _, line := range lines {
		norm := normalizeLine(line)
		if norm != line {
			changed = true
		}
		if norm == "" {
			blanks++
			if blanks > maxBlank {
				changed = true
				continue
			}
		} else {
			blanks = 0
		}
		out = append(out, norm)
	}
	if !changed {
		return content
	}
	return strings.Join(out, "\n")
}

// normalizeLine trims trailing whitespace from a single line, keeping exactly
// two trailing spaces when the original line ended in a Markdown hard break
// (two or more spaces after non-whitespace content).
func normalizeLine(line string) string {
	trimmed := strings.TrimRight(line, " \t")
	if trimmed == "" || trimmed == line {
		return trimmed
	}
	if strings.HasSuffix(line, "  ") {
		return trimmed + "  "
	}
	return trimmed
}

// mayNeedNormalization is a cheap pre-scan that lets normalizeWhitespace skip
// the split/join allocation entirely for content that is already clean — the
// common case once a conversation's history has been compressed on a previous
// turn. False positives only cost the full pass; false negatives never occur.
func mayNeedNormalization(content string, maxBlank int) bool {
	if strings.Contains(content, " \n") || strings.Contains(content, "\t\n") {
		return true
	}
	if strings.HasSuffix(content, " ") || strings.HasSuffix(content, "\t") {
		return true
	}
	// A run of more than maxBlank blank lines is maxBlank+2 consecutive
	// newlines. Blank lines containing spaces or tabs are caught above.
	return strings.Contains(content, strings.Repeat("\n", maxBlank+2))
}
