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

// Package gitx reads the git state the hooks need: added lines, the current
// branch and when it was created.
package gitx

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Line is one line of content attributed to a file and line number.
type Line struct {
	Path string
	No   int
	Text string
}

// Run executes git with args and returns its stdout.
func Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // fixed binary; args are refs and paths from git
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

// AddedLines returns the lines the change under review adds to files.
//
// With PRE_COMMIT_FROM_REF and PRE_COMMIT_TO_REF set (pre-push, or
// `pre-commit run --from-ref --to-ref` in CI) it diffs that range. Otherwise it
// diffs the index. The diff covers the whole change, so a rename is detected
// even though only its new path is passed. A file in the diff contributes only
// its added lines: deletions, pure renames and mode changes add nothing. Files
// absent from the diff (for example under `pre-commit run --all-files`) are
// read whole, so an audit run sees every line.
func AddedLines(ctx context.Context, files []string) ([]Line, error) {
	if len(files) == 0 {
		return nil, nil
	}
	args := []string{"-c", "core.quotePath=false", "diff", "--no-color", "--no-ext-diff", "--diff-filter=ACMR"}
	from, to := os.Getenv("PRE_COMMIT_FROM_REF"), os.Getenv("PRE_COMMIT_TO_REF")
	if from != "" && to != "" {
		args = append(args, from+"..."+to)
	} else {
		args = append(args, "--cached")
	}
	out, err := Run(ctx, append(args, "-U0")...)
	if err != nil {
		return nil, err
	}
	names, err := Run(ctx, append(args, "--name-only")...)
	if err != nil {
		return nil, err
	}
	inDiff := make(map[string]bool)
	for _, n := range strings.Split(strings.TrimSpace(names), "\n") {
		if n != "" {
			inDiff[n] = true
		}
	}
	wanted := make(map[string]bool, len(files))
	for _, f := range files {
		wanted[f] = true
	}
	var lines []Line
	for _, l := range ParseAddedLines(out) {
		if wanted[l.Path] {
			lines = append(lines, l)
		}
	}
	for _, f := range files {
		if inDiff[f] {
			continue
		}
		whole, err := readLines(f)
		if err != nil {
			return nil, err
		}
		lines = append(lines, whole...)
	}
	return lines, nil
}

var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ParseAddedLines extracts the added lines from a unified diff produced with -U0.
func ParseAddedLines(diff string) []Line {
	var (
		lines []Line
		path  string
		next  int
	)
	sc := bufio.NewScanner(strings.NewReader(diff))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "+++ "):
			path = strings.TrimPrefix(strings.TrimPrefix(t, "+++ "), "b/")
			if path == "/dev/null" {
				path = ""
			}
		case strings.HasPrefix(t, "@@"):
			if m := hunkHeader.FindStringSubmatch(t); m != nil {
				next, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(t, "+") && path != "":
			lines = append(lines, Line{Path: path, No: next, Text: t[1:]})
			next++
		}
	}
	return lines
}

func readLines(path string) ([]Line, error) {
	data, err := os.ReadFile(path) //nolint:gosec // paths come from git
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var lines []Line
	for i, t := range strings.Split(string(data), "\n") {
		lines = append(lines, Line{Path: path, No: i + 1, Text: t})
	}
	return lines, nil
}

// CurrentBranch returns the checked-out branch, or "" on a detached HEAD.
func CurrentBranch(ctx context.Context) (string, error) {
	out, err := Run(ctx, "symbolic-ref", "--short", "-q", "HEAD")
	if err != nil {
		return "", nil //nolint:nilerr // a detached HEAD makes symbolic-ref exit 1
	}
	return strings.TrimSpace(out), nil
}

// BranchCreated returns when the local branch was created, read from its
// reflog. ok is false when the reflog has no entries for it.
func BranchCreated(ctx context.Context, branch string) (created time.Time, ok bool) {
	out, err := Run(ctx, "reflog", "show", "--date=unix", "--format=%gd", "refs/heads/"+branch)
	if err != nil {
		return time.Time{}, false
	}
	entries := strings.Fields(out)
	if len(entries) == 0 {
		return time.Time{}, false
	}
	oldest := entries[len(entries)-1]
	open, closing := strings.LastIndex(oldest, "{"), strings.LastIndex(oldest, "}")
	if open < 0 || closing <= open {
		return time.Time{}, false
	}
	secs, err := strconv.ParseInt(oldest[open+1:closing], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(secs, 0), true
}
