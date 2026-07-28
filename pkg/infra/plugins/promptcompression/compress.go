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

// contentKind is the coarse content classification the router assigns to a
// message before choosing transforms.
type contentKind int

const (
	kindProse contentKind = iota
	kindJSON
)

// ansiEscape matches ANSI CSI/OSC escape sequences (colors, cursor movement)
// that captured terminal output and CI logs carry but models never need.
var ansiEscape = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)

// fencedJSONBlock matches ```json ... ``` fenced blocks so JSON embedded in
// prose (typical of tool outputs pasted into messages) can be compacted
// without touching the surrounding text.
var fencedJSONBlock = regexp.MustCompile("(?s)```json[ \t]*\\n(.*?)\\n[ \t]*```")

// classify routes content to a kind. Only unambiguous standalone JSON objects
// or arrays are classified as JSON; everything else is prose.
func classify(content string) contentKind {
	trimmed := strings.TrimSpace(content)
	if len(trimmed) < 2 {
		return kindProse
	}
	first := trimmed[0]
	if (first == '{' || first == '[') && json.Valid([]byte(trimmed)) {
		return kindJSON
	}
	return kindProse
}

// compressContent applies the configured transforms to a single message body
// and reports whether anything changed. Transforms are ordered so structural
// work (JSON) happens before textual cleanup, and every step is deterministic.
func compressContent(content string, cfg Settings) (string, bool) {
	if len(content) < cfg.MinLength {
		return content, false
	}
	out := content
	if cfg.StripANSI {
		out = ansiEscape.ReplaceAllString(out, "")
	}
	if cfg.CompressJSON {
		switch classify(out) {
		case kindJSON:
			out = compactJSON(out)
		case kindProse:
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
// failure the original text is returned untouched.
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
		if !json.Valid([]byte(strings.TrimSpace(inner))) {
			return block
		}
		compacted := compactJSON(inner)
		if compacted == inner {
			return block
		}
		return "```json\n" + compacted + "\n```"
	})
}

// normalizeWhitespace trims trailing spaces and tabs from every line and caps
// runs of blank lines at maxBlank. Leading whitespace (indentation) is
// preserved because it can be semantically meaningful (code, YAML, Markdown).
func normalizeWhitespace(content string, maxBlank int) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	blanks := 0
	for _, line := range lines {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			blanks++
			if blanks > maxBlank {
				continue
			}
		} else {
			blanks = 0
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
