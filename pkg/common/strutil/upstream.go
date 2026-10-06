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

package strutil

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// SanitizeUpstream makes text that came from a third party safe to reflect: it
// drops control and non-printable runes (log and terminal injection, header
// smuggling), collapses whitespace runs and cuts the result to max bytes on a
// rune boundary. A tenant-chosen identity provider controls this text, so it
// must neither carry a payload nor be large enough to exfiltrate a response.
func SanitizeUpstream(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			continue
		}
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// IsBoundedPrintable reports whether s is non-empty, at most max bytes and made
// only of printable, non-space-padded runes.
func IsBoundedPrintable(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
