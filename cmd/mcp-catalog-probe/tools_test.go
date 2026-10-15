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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func mcpServer(t *testing.T, tools ...string) string {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	for _, name := range tools {
		server.AddTool(&mcp.Tool{Name: name, Description: "Does " + name + ". More detail follows here.", InputSchema: map[string]any{"type": "object"}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return &mcp.CallToolResult{}, nil })
	}
	srv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProbeTools_ReportsBothDirectionsOfDrift(t *testing.T) {
	t.Parallel()
	url := mcpServer(t, "read_wiki_structure", "ask_wiki_question")

	r := probeTools(5*time.Second, map[string]any{
		"name":       "com.deepwiki/mcp",
		"server_url": url,
		"transport":  "streamable-http",
		"tools":      []any{map[string]any{"name": "read_wiki_structure"}, map[string]any{"name": "ask_question"}},
	})

	if r.Status != toolsStatusListed {
		t.Fatalf("status = %s (%s), want listed", r.Status, r.Detail)
	}
	if !reflect.DeepEqual(r.OnlyInCatalog, []string{"ask_question"}) || !reflect.DeepEqual(r.OnlyUpstream, []string{"ask_wiki_question"}) {
		t.Fatalf("diff = %v / %v", r.OnlyInCatalog, r.OnlyUpstream)
	}
	if !r.drifted() {
		t.Fatal("a renamed tool is drift")
	}
	for _, tool := range r.upstream {
		if tool.Name == "ask_wiki_question" && tool.Description != "Does ask_wiki_question." {
			t.Fatalf("upstream description = %q, want its first sentence", tool.Description)
		}
	}
}

func TestProbeTools_AuthChallengeIsNotAFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x.example/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	r := probeTools(5*time.Second, map[string]any{"name": "com.example/mcp", "server_url": srv.URL, "transport": "streamable-http"})

	if r.Status != toolsStatusAuthRequired || r.drifted() {
		t.Fatalf("status = %s (%s), want auth_required and no drift", r.Status, r.Detail)
	}
}

func TestToolsResultDrifted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    toolsResult
		want bool
	}{
		{"in sync", toolsResult{Status: toolsStatusListed}, false},
		{"catalog-only name", toolsResult{Status: toolsStatusListed, OnlyInCatalog: []string{"x"}}, true},
		{"missing upstream tool", toolsResult{Status: toolsStatusListed, OnlyUpstream: []string{"x"}}, true},
		{"partial server hides keyed tools", toolsResult{Status: toolsStatusListed, Partial: true, OnlyInCatalog: []string{"x"}}, false},
		{"partial server still misses a tool", toolsResult{Status: toolsStatusListed, Partial: true, OnlyUpstream: []string{"x"}}, true},
		{"not listed", toolsResult{Status: toolsStatusAuthRequired, OnlyInCatalog: []string{"x"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.r.drifted(); got != tc.want {
				t.Fatalf("drifted() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMergeTools(t *testing.T) {
	t.Parallel()
	catalog := []catalogTool{{Name: "a", Description: "curated"}, {Name: "gone", Description: "old"}}
	upstream := []catalogTool{{Name: "b", Description: "upstream b"}, {Name: "a", Description: "upstream a"}}

	got := mergeTools(catalog, upstream, false)
	want := []any{
		map[string]any{"name": "b", "description": "upstream b"},
		map[string]any{"name": "a", "description": "curated"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %v, want %v", got, want)
	}

	partial := mergeTools(catalog, upstream, true)
	if len(partial) != 3 || partial[2].(map[string]any)["name"] != "gone" {
		t.Fatalf("partial merge must keep the catalog's extra tools: %v", partial)
	}
}

func TestShortDescription(t *testing.T) {
	t.Parallel()
	if got := shortDescription("Search the web.\n  Returns results. Use it often."); got != "Search the web." {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("x", 300)
	if got := shortDescription(long); len([]rune(got)) != maxToolDescriptionRunes || !strings.HasSuffix(got, "…") {
		t.Fatalf("long description not cut to %d runes: %d", maxToolDescriptionRunes, len([]rune(got)))
	}
}

// The catalog is hand-edited and reviewed as text: a tool fix must not reorder
// keys, re-escape "&" or reflow any other entry.
func TestRewriteCatalog_KeepsTheFileLayout(t *testing.T) {
	t.Parallel()
	const original = `{
  "servers": [
    {
      "name": "com.a/mcp",
      "vendor": "A & B",
      "tools": [
        {
          "name": "old"
        }
      ],
      "server_url": "https://a.example/mcp"
    },
    {
      "name": "com.b/mcp",
      "vendor": "Ünïcode",
      "server_url": "https://b.example/mcp"
    }
  ]
}
`
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if n := rewriteCatalog(path, func(int, *orderedObject) bool { return false }); n != 0 {
		t.Fatalf("changed = %d", n)
	}
	unchanged, _ := os.ReadFile(path)
	if string(unchanged) != original {
		t.Fatalf("a no-op rewrite changed the file:\n%s", unchanged)
	}

	rewriteCatalog(path, func(i int, s *orderedObject) bool {
		if i != 0 {
			return false
		}
		s.set("tools", []any{map[string]any{"name": "new"}})
		return true
	})
	got, _ := os.ReadFile(path)
	want := strings.Replace(original, `"name": "old"`, `"name": "new"`, 1)
	if string(got) != want {
		t.Fatalf("rewrite touched more than the tools:\n%s", got)
	}
}
