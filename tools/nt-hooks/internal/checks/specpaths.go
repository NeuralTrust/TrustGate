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
	"bufio"
	"bytes"
	"path"
	"strings"
)

// SpecOptions configures ClassifySpecPath.
type SpecOptions struct {
	// Public also blocks agent configuration directories.
	Public bool
	// Allow lists path globs that are always accepted.
	Allow []string
}

var (
	sddDirs        = []string{"openspec", "specs", ".sdd"}
	agentDirs      = []string{".cursor", ".claude"}
	sddBasenames   = []string{"proposal.md", "design.md", "tasks.md", "spec.md"}
	sddFrontmatter = []string{"change:", "phase:"}
)

// ClassifySpecPath reports why p must not be committed, or "" when it may.
//
// Precedence: explicit allow globs, then agent directories (public repos
// only), then SDD directories, then the documentation allowlist, then SDD
// file names and SDD frontmatter. content is read only for Markdown files.
func ClassifySpecPath(p string, content []byte, opts SpecOptions) string {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	for _, g := range opts.Allow {
		if globMatch(g, p) {
			return ""
		}
	}
	segments := strings.Split(p, "/")
	dirs := segments[:len(segments)-1]
	base := segments[len(segments)-1]
	if opts.Public {
		if d := firstIn(dirs, agentDirs); d != "" {
			return "agent configuration (" + d + "/) must not be published in a public repo"
		}
	}
	if d := firstIn(dirs, sddDirs); d != "" {
		return "spec-driven development artifacts (" + d + "/) live outside the repo"
	}
	if isDocPath(segments, base) {
		return ""
	}
	if contains(sddBasenames, strings.ToLower(base)) {
		return "spec-driven development file (" + base + ") lives outside the repo"
	}
	if strings.EqualFold(path.Ext(base), ".md") && hasSDDFrontmatter(content) {
		return "Markdown with spec-driven development frontmatter lives outside the repo"
	}
	return ""
}

func isDocPath(segments []string, base string) bool {
	if segments[0] == "docs" {
		return true
	}
	upper := strings.ToUpper(base)
	return strings.HasPrefix(upper, "README") || strings.HasPrefix(upper, "CHANGELOG") ||
		upper == "AGENTS.MD" || upper == "CLAUDE.MD"
}

func hasSDDFrontmatter(content []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(content))
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "---" {
		return false
	}
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "---" {
			return false
		}
		for _, k := range sddFrontmatter {
			if strings.HasPrefix(t, k) {
				return true
			}
		}
	}
	return false
}

func globMatch(glob, p string) bool {
	if prefix, ok := strings.CutSuffix(glob, "/**"); ok {
		return p == prefix || strings.HasPrefix(p, prefix+"/")
	}
	ok, err := path.Match(glob, p)
	return err == nil && ok
}

func firstIn(dirs, names []string) string {
	for _, d := range dirs {
		if contains(names, d) {
			return d
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
