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

package checks

import (
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/tools/nt-hooks/internal/gitx"
)

// DefaultTicketPrefixes are the issue-tracker keys blocked when none are given.
var DefaultTicketPrefixes = []string{"ENG", "RUN"}

var trackerURL = regexp.MustCompile(`(?i)(linear\.app/|atlassian\.net)`)

// TicketPattern builds the case-insensitive key pattern for prefixes.
func TicketPattern(prefixes []string) *regexp.Regexp {
	quoted := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		if p = strings.TrimSpace(p); p != "" {
			quoted = append(quoted, regexp.QuoteMeta(p))
		}
	}
	return regexp.MustCompile(`(?i)\b(` + strings.Join(quoted, "|") + `)-\d+\b`)
}

// ScanTicketRefs reports issue-tracker keys and tracker URLs in lines.
func ScanTicketRefs(lines []gitx.Line, prefixes []string) []Finding {
	key := TicketPattern(prefixes)
	var out []Finding
	for _, l := range lines {
		if strings.Contains(l.Text, EscapeMarker) {
			continue
		}
		if m := key.FindString(l.Text); m != "" {
			out = append(out, at(l, "ticket key "+m+" in content; keep ticket keys in branch names, commits and PRs"))
			continue
		}
		if m := trackerURL.FindString(l.Text); m != "" {
			out = append(out, at(l, "issue-tracker link ("+m+") in content"))
		}
	}
	return out
}
