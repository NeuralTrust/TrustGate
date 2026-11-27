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
	"fmt"
	"regexp"
	"strings"
)

// BranchTypes are the prefixes a branch name may start with.
var BranchTypes = []string{"feat", "fix", "chore", "refactor", "docs", "test", "ci", "build", "perf", "security", "hotfix"}

var (
	branchPattern = regexp.MustCompile(`^(` + strings.Join(BranchTypes, "|") + `)/[a-z0-9]+(-[a-z0-9]+)*$`)
	nonSlug       = regexp.MustCompile(`[^a-z0-9]+`)
)

// BranchExempt reports whether name is exempt from the naming rule.
func BranchExempt(name string) bool {
	return name == "" || name == "main" || name == "develop" || strings.HasPrefix(name, "dependabot/")
}

// CheckBranchName validates name as <type>/<slug>. On failure it returns an
// error carrying a suggested replacement name.
func CheckBranchName(name string) error {
	if BranchExempt(name) || branchPattern.MatchString(name) {
		return nil
	}
	return fmt.Errorf("branch %q must be <type>/<slug> with type one of %s and a lowercase slug; rename with: git branch -m %s",
		name, strings.Join(BranchTypes, ", "), SuggestBranchName(name))
}

// SuggestBranchName turns name into a valid branch name. A leading valid type
// is kept; any other leading segment (a user or tool name) is dropped and the
// type defaults to feat.
func SuggestBranchName(name string) string {
	parts := strings.Split(strings.ToLower(name), "/")
	typ := "feat"
	rest := parts
	if len(parts) > 1 {
		if isBranchType(parts[0]) {
			typ = parts[0]
		}
		rest = parts[1:]
	}
	slug := strings.Trim(nonSlug.ReplaceAllString(strings.Join(rest, "-"), "-"), "-")
	if slug == "" {
		slug = "change"
	}
	return typ + "/" + slug
}

func isBranchType(s string) bool {
	for _, t := range BranchTypes {
		if s == t {
			return true
		}
	}
	return false
}
