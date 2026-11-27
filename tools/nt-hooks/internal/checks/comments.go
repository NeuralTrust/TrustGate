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

var (
	bannerComment    = regexp.MustCompile(`^\s*//\s*[=-]{4,}\s*$`)
	codeLikeComment  = regexp.MustCompile(`^\s*//\s+([a-zA-Z_][a-zA-Z0-9_.]*\s*(:=|=[^=])|[a-zA-Z_][a-zA-Z0-9_.]*\(|return |if |for |\}|func )`)
	directiveComment = regexp.MustCompile(`//\s*(@|go:|nolint|\+build|export |TODO|FIXME|NOTE|XXX|Deprecated)`)
	generatedGoFile  = regexp.MustCompile(`(\.pb\.go$|_gen\.go$|_mock\.go$|/mocks/)`)
)

// ScanComments reports decorative banner comments and likely commented-out
// code in Go lines. Generated files are skipped.
func ScanComments(lines []gitx.Line) []Finding {
	var out []Finding
	for _, l := range lines {
		if !strings.HasSuffix(l.Path, ".go") || generatedGoFile.MatchString(l.Path) {
			continue
		}
		switch {
		case bannerComment.MatchString(l.Text):
			out = append(out, at(l, "decorative banner comment"))
		case codeLikeComment.MatchString(l.Text) && !directiveComment.MatchString(l.Text):
			out = append(out, at(l, "likely commented-out code; delete it, git keeps history"))
		}
	}
	return out
}
