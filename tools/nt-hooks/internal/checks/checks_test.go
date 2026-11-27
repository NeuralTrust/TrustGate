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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/tools/nt-hooks/internal/gitx"
)

func TestCheckCommitMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		msg  string
		ok   bool
	}{
		{"feat", "feat: add hook", true},
		{"scope and breaking", "fix(gateway)!: drop legacy header", true},
		{"ticket key in subject is fine", "chore: bump deps (ENG-12)", true},
		{"git comments skipped", "# Please enter\n\nrefactor: split parser\n\nbody", true},
		{"merge branch", "Merge branch 'main' into develop", true},
		{"merge pull request", "Merge pull request #12 from org/feat/x", true},
		{"revert", `Revert "feat: add hook"`, true},
		{"fixup", "fixup! feat: add hook", true},
		{"missing type", "add hook", false},
		{"unknown type", "feature: add hook", false},
		{"no space after colon", "feat:add hook", false},
		{"empty subject", "feat: ", false},
		{"uppercase type", "Feat: add hook", false},
		{"empty", "\n# only comments\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := CheckCommitMessage(tt.msg); (err == nil) != tt.ok {
				t.Fatalf("CheckCommitMessage(%q) error = %v, want ok=%v", tt.msg, err, tt.ok)
			}
		})
	}
}

func TestCheckBranchName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		branch  string
		ok      bool
		suggest string
	}{
		{"feat with ticket", "feat/abc-123-remove-token", true, ""},
		{"hotfix", "hotfix/abc-7-client-credentials", true, ""},
		{"security", "security/rotate-keys", true, ""},
		{"main", "main", true, ""},
		{"develop", "develop", true, ""},
		{"dependabot", "dependabot/go_modules/golang.org/x/net-0.60.0", true, ""},
		{"detached", "", true, ""},
		{"user prefix", "jdoe/abc-123-remove-token", false, "feat/abc-123-remove-token"},
		{"tool prefix", "claude/Fix_Stuff", false, "feat/fix-stuff"},
		{"uppercase ticket", "fix/ENG-12-bug", false, "fix/eng-12-bug"},
		{"no type", "quick-fix", false, "feat/quick-fix"},
		{"nested", "feat/area/thing", false, "feat/area-thing"},
		{"trailing dash", "feat/thing-", false, "feat/thing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckBranchName(tt.branch)
			if (err == nil) != tt.ok {
				t.Fatalf("CheckBranchName(%q) error = %v, want ok=%v", tt.branch, err, tt.ok)
			}
			if !tt.ok {
				if got := SuggestBranchName(tt.branch); got != tt.suggest {
					t.Fatalf("SuggestBranchName(%q) = %q, want %q", tt.branch, got, tt.suggest)
				}
				if CheckBranchName(tt.suggest) != nil {
					t.Fatalf("suggestion %q is itself invalid", tt.suggest)
				}
			}
		})
	}
}

func lines(path string, texts ...string) []gitx.Line {
	out := make([]gitx.Line, 0, len(texts))
	for i, t := range texts {
		out = append(out, gitx.Line{Path: path, No: i + 1, Text: t})
	}
	return out
}

func TestScanTicketRefs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		text     string
		prefixes []string
		want     int
	}{
		{"eng key in comment", "// workaround for ENG-1234", DefaultTicketPrefixes, 1},
		{"run key lowercase", "# see run-77", DefaultTicketPrefixes, 1},
		{"linear url", "// https://linear.app/acme/issue/X", DefaultTicketPrefixes, 1},
		{"jira url", "see https://acme.atlassian.net/browse/X", DefaultTicketPrefixes, 1},
		{"sha-256 is not a key", "// hash with SHA-256", DefaultTicketPrefixes, 0},
		{"utf-8 is not a key", "// UTF-8 input", DefaultTicketPrefixes, 0},
		{"cve is not a key", "// fixes CVE-2024-1234", DefaultTicketPrefixes, 0},
		{"word boundary", "// RERUN-12 is not RUN-12", DefaultTicketPrefixes, 1},
		{"no false hit inside word", "// RERUN-12", DefaultTicketPrefixes, 0},
		{"escape hatch", "// ENG-1 nolint:confidential", DefaultTicketPrefixes, 0},
		{"custom prefix", "// OPS-9", []string{"OPS"}, 1},
		{"custom prefix ignores defaults", "// ENG-9", []string{"OPS"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ScanTicketRefs(lines("a.go", tt.text), tt.prefixes)
			if len(got) != tt.want {
				t.Fatalf("ScanTicketRefs(%q) = %v, want %d findings", tt.text, got, tt.want)
			}
		})
	}
}

func TestClassifySpecPath(t *testing.T) {
	t.Parallel()
	sdd := []byte("---\nchange: add-thing\nphase: design\n---\n# Title\n")
	plain := []byte("---\ntitle: Guide\n---\n# Title\n")
	tests := []struct {
		name    string
		path    string
		content []byte
		opts    SpecOptions
		blocked bool
	}{
		{"openspec root", "openspec/changes/x/proposal.md", nil, SpecOptions{}, true},
		{"nested specs", "api/specs/thing.yaml", nil, SpecOptions{}, true},
		{"sdd dir", ".sdd/state.json", nil, SpecOptions{}, true},
		{"design.md anywhere", "pkg/feature/design.md", nil, SpecOptions{}, true},
		{"tasks.md root", "tasks.md", nil, SpecOptions{}, true},
		{"design.md under docs allowed", "docs/architecture/design.md", nil, SpecOptions{}, false},
		{"openspec under docs still blocked", "docs/openspec/x.md", nil, SpecOptions{}, true},
		{"readme", "pkg/README.md", nil, SpecOptions{}, false},
		{"agents.md", ".agents/AGENTS.md", nil, SpecOptions{}, false},
		{"sdd frontmatter", "notes/plan.md", sdd, SpecOptions{}, true},
		{"plain frontmatter", "notes/guide.md", plain, SpecOptions{}, false},
		{"go file", "pkg/spec.go", nil, SpecOptions{}, false},
		{"cursor private ok", ".cursor/rules/x.mdc", nil, SpecOptions{}, false},
		{"cursor public blocked", ".cursor/rules/x.mdc", nil, SpecOptions{Public: true}, true},
		{"claude public blocked", ".claude/settings.json", nil, SpecOptions{Public: true}, true},
		{"explicit allow wins", "api/specs/openapi.yaml", nil, SpecOptions{Allow: []string{"api/specs/**"}}, false},
		{"explicit allow wins over public", ".cursor/x.mdc", nil, SpecOptions{Public: true, Allow: []string{".cursor/**"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifySpecPath(tt.path, tt.content, tt.opts)
			if (got != "") != tt.blocked {
				t.Fatalf("ClassifySpecPath(%q) = %q, want blocked=%v", tt.path, got, tt.blocked)
			}
		})
	}
}

func TestScanInternalHosts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		text  string
		allow []string
		want  int
	}{
		{"10/8", `addr := "10.12.0.5:8080"`, nil, 1},
		{"172.16/12", "host: 172.20.1.1", nil, 1},
		{"172 outside range", "host: 172.32.1.1", nil, 0},
		{"192.168", "url: http://192.168.1.10", nil, 1},
		{"public ip", "dns: 8.8.8.8", nil, 0},
		{"cluster local", "redis.cache.svc.cluster.local:6379", nil, 1},
		{"dot internal", "api.corp.internal", nil, 1},
		{"go internal package", `import "github.com/acme/x/internal/y"`, nil, 0},
		{"grpc code", "return status.Error(codes.Internal, msg)", nil, 0},
		{"lowercase selector", "v := s.internal", nil, 0},
		{"gcp metadata allowed", "http://metadata.google.internal/computeMetadata", DefaultHostAllow, 0},
		{"custom allow suffix", "svc.dev.internal", []string{"dev.internal"}, 0},
		{"escape hatch", "10.0.0.1 nolint:confidential", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ScanInternalHosts(lines("a.yaml", tt.text), tt.allow)
			if len(got) != tt.want {
				t.Fatalf("ScanInternalHosts(%q) = %v, want %d findings", tt.text, got, tt.want)
			}
		})
	}
}

func TestScanComments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		text string
		want int
	}{
		{"banner", "a.go", "// =====", 1},
		{"dash banner", "a.go", "  // ------  ", 1},
		{"assignment", "a.go", "// x := compute()", 1},
		{"call", "a.go", "\t// doThing(ctx)", 1},
		{"return", "a.go", "// return nil", 1},
		{"doc comment", "a.go", "// Parse reads the config file.", 0},
		{"todo", "a.go", "// TODO(x): handle retries", 0},
		{"nolint", "a.go", "//nolint:errcheck", 0},
		{"swagger", "a.go", "// @Router /v1/x [get]", 0},
		{"generated skipped", "a.pb.go", "// x := 1", 0},
		{"non go skipped", "a.md", "// x := 1", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ScanComments(lines(tt.path, tt.text))
			if len(got) != tt.want {
				t.Fatalf("ScanComments(%q) = %v, want %d findings", tt.text, got, tt.want)
			}
		})
	}
}

func TestFindingString(t *testing.T) {
	t.Parallel()
	if got := (Finding{Path: "a.go", Line: 3, Msg: "m"}).String(); got != "a.go:3: m" {
		t.Fatalf("got %q", got)
	}
	if got := (Finding{Path: "a.go", Msg: "m"}).String(); !strings.HasPrefix(got, "a.go: ") {
		t.Fatalf("got %q", got)
	}
}
