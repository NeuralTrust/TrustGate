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

// Command nt-hooks runs the deterministic pre-commit checks shared by the
// NeuralTrust Go repositories.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/tools/nt-hooks/internal/checks"
	"github.com/NeuralTrust/TrustGate/tools/nt-hooks/internal/gitx"
)

const usage = `usage: nt-hooks <command> [flags] [files...]

commands:
  commit-msg <file>         Conventional Commits subject
  commit-range <from> <to>  Conventional Commits for every non-merge commit in from..to
  branch-name               <type>/<slug> branch name
  ticket-refs [files]       issue-tracker keys and links in added lines
  spec-paths [files]        spec-driven development artifacts
  internal-hosts [files]    private addresses and cluster host names in added lines
  comment-policy [files]    banner comments and commented-out Go code in added lines
`

var errViolations = errors.New("violations found")

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		_, _ = fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	err := run(ctx, os.Args[1], os.Args[2:], os.Stdout, os.Stderr)
	switch {
	case err == nil:
	case errors.Is(err, errViolations):
		os.Exit(1)
	default:
		_, _ = fmt.Fprintln(os.Stderr, "nt-hooks:", err)
		os.Exit(2)
	}
}

func run(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) error {
	switch cmd {
	case "commit-msg":
		return runCommitMsg(args, stderr)
	case "commit-range":
		return runCommitRange(ctx, args, stderr)
	case "branch-name":
		return runBranchName(ctx, args, stderr)
	case "ticket-refs":
		return runTicketRefs(ctx, args, stderr)
	case "spec-paths":
		return runSpecPaths(args, stderr)
	case "internal-hosts":
		return runInternalHosts(ctx, args, stdout, stderr)
	case "comment-policy":
		return runCommentPolicy(ctx, args, stderr)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func runCommitMsg(args []string, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("commit-msg needs the commit message file")
	}
	data, err := os.ReadFile(args[0]) // #nosec G703 -- git passes the commit message path
	if err != nil {
		return fmt.Errorf("reading commit message: %w", err)
	}
	if err := checks.CheckCommitMessage(string(data)); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return errViolations
	}
	return nil
}

func runCommitRange(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) != 2 {
		return errors.New("commit-range needs <from> <to>")
	}
	out, err := gitx.Run(ctx, "log", "--no-merges", "--format=%h%x00%s", args[0]+".."+args[1])
	if err != nil {
		return err
	}
	failed := false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		hash, subject, ok := strings.Cut(line, "\x00")
		if !ok {
			continue
		}
		if err := checks.CheckCommitMessage(subject); err != nil {
			_, _ = fmt.Fprintf(stderr, "%s: %v\n", hash, err)
			failed = true
		}
	}
	if failed {
		return errViolations
	}
	return nil
}

func runBranchName(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("branch-name", flag.ContinueOnError)
	branch := fs.String("branch", "", "branch to check (default: the checked-out branch)")
	createdAfter := fs.String("created-after", "", "only enforce on local branches created on or after this date (YYYY-MM-DD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := *branch
	if name == "" {
		var err error
		if name, err = gitx.CurrentBranch(ctx); err != nil {
			return err
		}
		if *createdAfter != "" && name != "" {
			cutoff, err := time.Parse(time.DateOnly, *createdAfter)
			if err != nil {
				return fmt.Errorf("parsing -created-after: %w", err)
			}
			if created, ok := gitx.BranchCreated(ctx, name); ok && created.Before(cutoff) {
				return nil
			}
		}
	}
	if err := checks.CheckBranchName(name); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return errViolations
	}
	return nil
}

func runTicketRefs(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("ticket-refs", flag.ContinueOnError)
	var prefixes stringList
	fs.Var(&prefixes, "prefix", "issue-tracker key prefix to block (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(prefixes) == 0 {
		prefixes = checks.DefaultTicketPrefixes
	}
	lines, err := gitx.AddedLines(ctx, fs.Args())
	if err != nil {
		return err
	}
	return report(stderr, checks.ScanTicketRefs(lines, prefixes), "")
}

func runSpecPaths(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("spec-paths", flag.ContinueOnError)
	public := fs.Bool("public", false, "also block agent configuration directories")
	var allow stringList
	fs.Var(&allow, "allow", "path glob that is always accepted (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := checks.SpecOptions{Public: *public, Allow: allow}
	var findings []checks.Finding
	for _, p := range fs.Args() {
		var content []byte
		if strings.EqualFold(filepath.Ext(p), ".md") {
			content, _ = os.ReadFile(p) //nolint:gosec // paths come from git, read-only
		}
		if reason := checks.ClassifySpecPath(p, content, opts); reason != "" {
			findings = append(findings, checks.Finding{Path: p, Msg: reason})
		}
	}
	return report(stderr, findings, "")
}

func runInternalHosts(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("internal-hosts", flag.ContinueOnError)
	strict := fs.Bool("strict", false, "fail instead of warning")
	var allow stringList
	fs.Var(&allow, "allow", "host or domain to accept (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	lines, err := gitx.AddedLines(ctx, fs.Args())
	if err != nil {
		return err
	}
	findings := checks.ScanInternalHosts(lines, append(allow, checks.DefaultHostAllow...))
	if !*strict {
		return report(stdout, findings, "warning: ")
	}
	return report(stderr, findings, "")
}

func runCommentPolicy(ctx context.Context, args []string, stderr io.Writer) error {
	lines, err := gitx.AddedLines(ctx, args)
	if err != nil {
		return err
	}
	return report(stderr, checks.ScanComments(lines), "")
}

func report(w io.Writer, findings []checks.Finding, warnPrefix string) error {
	for _, f := range findings {
		_, _ = fmt.Fprintln(w, warnPrefix+f.String())
	}
	if len(findings) == 0 || warnPrefix != "" {
		return nil
	}
	return errViolations
}
