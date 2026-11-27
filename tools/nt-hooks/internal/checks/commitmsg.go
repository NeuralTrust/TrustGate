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
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CommitTypes are the Conventional Commits types accepted for commit messages.
// They match the PR title rule in the shared pr-metadata workflow.
var CommitTypes = []string{"fix", "feat", "build", "chore", "ci", "docs", "style", "refactor", "perf", "test"}

var (
	conventionalSubject = regexp.MustCompile(`^(` + strings.Join(CommitTypes, "|") + `)(\([^()]+\))?!?: \S`)
	exemptSubject       = regexp.MustCompile(`^(Merge (branch|pull request|remote-tracking branch|tag)\b|Revert "|(fixup|squash|amend)! )`)
)

// ErrEmptyCommitMessage is returned when the message has no subject line.
var ErrEmptyCommitMessage = errors.New("commit message is empty")

// CommitSubject returns the first line of msg that is not blank or a git comment.
func CommitSubject(msg string) string {
	for _, line := range strings.Split(msg, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return t
	}
	return ""
}

// CheckCommitMessage validates the subject of msg against Conventional Commits.
// Merge commits, reverts and fixup!/squash!/amend! commits are exempt.
func CheckCommitMessage(msg string) error {
	subject := CommitSubject(msg)
	if subject == "" {
		return ErrEmptyCommitMessage
	}
	if exemptSubject.MatchString(subject) || conventionalSubject.MatchString(subject) {
		return nil
	}
	return fmt.Errorf("commit subject %q is not Conventional Commits: use <type>(<scope>)!: <subject> with type one of %s",
		subject, strings.Join(CommitTypes, ", "))
}
