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

package mcp

import (
	"context"
	"strings"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// namedFor is the name a tool is exposed under: its server, then itself.
func namedFor(reg *registrydomain.Registry, name string) string {
	return exposedNameFor(name, reg).String()
}

func TestSlugFromCatalogCode(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"com.notion/mcp":                      "notion",
		"io.aha/mcp":                          "aha",
		"ai.airbyte/agents":                   "airbyte_agents",
		"com.google_cloud/developerknowledge": "google_cloud_developerknowledge",
		"com.cloudflare/observability":        "cloudflare_observability",
		// A code with nothing in front of the name keeps all of it.
		"snowflake": "snowflake",
		"":          "",
		"///":       "",
	}
	for code, want := range cases {
		if got := slugFromCatalogCode(code); got != want {
			t.Fatalf("slug(%q) = %q, want %q", code, got, want)
		}
	}
}

// A tool's name is the client's handle on it, so it must depend on the tool and
// nothing else. It used to depend on how many servers the caller had —
// installing a second one renamed every tool of the first, leaving an open
// conversation calling tools that no longer existed — and qualifying only on a
// collision would have made it depend on whether the colliding server was
// reachable. Spelling the server out every time is what removes the dependency.
func TestExposedName_CarriesItsServerWhateverElseIsBound(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "Notion", "https://notion.example/mcp")
	notion.MCPTarget.Code = "com.notion/mcp"

	if got := exposedNameFor("notion-search", notion).String(); got != "notion_notion-search" {
		t.Fatalf("name = %q, want notion_notion-search", got)
	}
	// Nothing about the name can change when the estate around it does, because
	// nothing about the estate went into it.
	linear := mcpRegistry(t, "Linear", "https://linear.example/mcp")
	linear.MCPTarget.Code = "com.linear/mcp"
	if got := exposedNameFor("notion-search", notion).String(); got != "notion_notion-search" {
		t.Fatalf("name = %q after binding Linear, want it unchanged", got)
	}
	if got := exposedNameFor("list_issues", linear).String(); got != "linear_list_issues" {
		t.Fatalf("name = %q, want linear_list_issues", got)
	}
}

// An admin renames an instance; the tools keep their names. The catalog code is
// what identifies a server, and that is not the admin's to edit.
func TestExposedName_SurvivesARename(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "Notion", "https://notion.example/mcp")
	reg.MCPTarget.Code = "com.notion/mcp"
	before := exposedNameFor("search", reg).String()
	reg.Name = "Notion (marketing workspace)"
	if after := exposedNameFor("search", reg).String(); after != before {
		t.Fatalf("rename changed the tool name: %q -> %q", before, after)
	}
}

// Several instances of one code share their catalog name, so each takes a
// digest of its own registry to stay apart from its siblings.
func TestExposedName_InstancesOfOneCodeStayApart(t *testing.T) {
	t.Parallel()
	finance := perInstanceRegistry(t, "Snowflake (FINANCE)", "https://a.example.com/mcp", map[string]string{"schema": "FINANCE"})
	analytics := perInstanceRegistry(t, "Snowflake (ANALYTICS)", "https://b.example.com/mcp", map[string]string{"schema": "ANALYTICS"})

	a := exposedNameFor("query", finance).String()
	b := exposedNameFor("query", analytics).String()
	if a == b {
		t.Fatalf("two instances share the name %q", a)
	}
	for _, name := range []string{a, b} {
		if !strings.HasPrefix(name, "snowflake_") || !strings.HasSuffix(name, "_query") {
			t.Fatalf("name = %q, want snowflake_<instance>_query", name)
		}
	}
}

// A registry wired by hand has no catalog code, so there is nothing readable to
// build on — but the name still has to be stable and its own.
func TestExposedName_UncataloguedServerFallsBackToItsRegistry(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "Internal", "https://internal.example/mcp")
	reg.MCPTarget.Code = ""
	got := exposedNameFor("search", reg).String()
	if !strings.HasPrefix(got, "s") || !strings.HasSuffix(got, "_search") {
		t.Fatalf("name = %q, want s<digest>_search", got)
	}
	if got != exposedNameFor("search", reg).String() {
		t.Fatal("the fallback name is not stable")
	}
}

// A client will not accept a name past 64 characters, and a truncated stem must
// still tell two tools apart.
func TestExposedName_TooLongIsCutButStaysDistinct(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "Google Cloud", "https://gcp.example/mcp")
	reg.MCPTarget.Code = "com.google_cloud/developerknowledge"
	long := strings.Repeat("a", 40)
	one := exposedNameFor(long+"_one", reg).String()
	two := exposedNameFor(long+"_two", reg).String()

	for _, name := range []string{one, two} {
		if len(name) > 64 {
			t.Fatalf("name %q is %d characters, want at most 64", name, len(name))
		}
		if !strings.HasPrefix(name, "google_cloud_developerknowledge_") {
			t.Fatalf("name = %q, want the server kept whole", name)
		}
	}
	if one == two {
		t.Fatalf("two tools truncated to the same name %q", one)
	}
}

func perInstanceRegistry(t *testing.T, name, url string, cfg map[string]string) *registrydomain.Registry {
	t.Helper()
	reg := mcpRegistry(t, name, url)
	reg.MCPTarget.Code = "snowflake"
	reg.MCPTarget.InstanceConfig = cfg
	return reg
}

// Two instances of one catalog code expose their tools under a per-instance
// prefix. When one instance is unreachable the survivor keeps its prefix — the
// name a client cached must not flap with the sibling's availability.
func TestComposer_ListTools_PerInstanceNamesDoNotFlap(t *testing.T) {
	t.Parallel()
	finance := perInstanceRegistry(t, "Snowflake (FINANCE)", "https://a.example.com/mcp", map[string]string{"schema": "FINANCE"})
	analytics := perInstanceRegistry(t, "Snowflake (ANALYTICS)", "https://b.example.com/mcp", map[string]string{"schema": "ANALYTICS"})
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen}}

	bothUp := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("query")},
		"https://b.example.com/mcp": {tools: tools("query")},
	}})
	got, err := bothUp.ListTools(context.Background(), routable(consumer, finance, analytics))
	if err != nil {
		t.Fatalf("both up: %v", err)
	}
	if names := toolNames(got); len(names) != 2 || names[0] != namedFor(finance, "query") || names[1] != namedFor(analytics, "query") {
		t.Fatalf("both up: tools = %v, want [%s %s]", names, namedFor(finance, "query"), namedFor(analytics, "query"))
	}

	oneDown := newTestComposer(&fakeDialer{
		upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": {tools: tools("query")}},
		dialErr:   map[string]error{"https://b.example.com/mcp": ErrUnreachable},
	})
	got, err = oneDown.ListTools(context.Background(), routable(consumer, finance, analytics))
	if err != nil {
		t.Fatalf("one down: %v", err)
	}
	if names := toolNames(got); len(names) != 1 || names[0] != namedFor(finance, "query") {
		t.Fatalf("one down: tools = %v, want [%s]", names, namedFor(finance, "query"))
	}

	// And the prefixed name is callable, so a client that cached it keeps working.
	if _, err := oneDown.CallTool(context.Background(), routable(consumer, finance, analytics), namedFor(finance, "query"), nil); err != nil {
		t.Fatalf("calling the stable per-instance name: %v", err)
	}
}
