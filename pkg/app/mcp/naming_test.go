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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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

// Every prefix that fits is a candidate. notion_ai_search fits both notion and
// notion_ai; which one serves it is decided from the tools, not by keeping the
// longer prefix and dropping the other. A name with no server prefix belongs
// to nobody.
func TestRegistriesForExposedName_OverlappingPrefixesAreCandidates(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "Notion", "https://notion.example/mcp")
	notion.MCPTarget.Code = "com.notion/mcp"
	notionAI := mcpRegistry(t, "Notion AI", "https://notion-ai.example/mcp")
	notionAI.MCPTarget.Code = "com.notion_ai/mcp"

	owners := registriesForExposedName([]*registrydomain.Registry{notion, notionAI}, "notion_ai_search")
	if len(owners) != 2 || owners[0] != notion || owners[1] != notionAI {
		t.Fatalf("owners = %v, want Notion and Notion AI", owners)
	}
	owners = registriesForExposedName([]*registrydomain.Registry{notion, notionAI}, "notion_search")
	if len(owners) != 1 || owners[0] != notion {
		t.Fatalf("owners = %v, want Notion", owners)
	}
	if got := registriesForExposedName([]*registrydomain.Registry{notion, notionAI}, "does-not-exist"); len(got) != 0 {
		t.Fatalf("owners = %v, want none", got)
	}
}

// Two servers can spell different tools as one string. Only those names take a
// digest; everything else stays exactly the name it had with one server bound.
func TestResolveNames_CollisionSuffixOnlyOnOverlap(t *testing.T) {
	t.Parallel()
	google := mcpRegistry(t, "Google", "https://google.example/mcp")
	google.MCPTarget.Code = "com.google/mcp"
	drive := mcpRegistry(t, "Google Drive", "https://drive.example/mcp")
	drive.MCPTarget.Code = "com.google_drive/mcp"

	got := resolveNames([]binding{
		{registry: google, tool: Tool{Name: "drive_list"}, exposed: "drive_list"},
		{registry: google, tool: Tool{Name: "search"}, exposed: "search"},
		{registry: drive, tool: Tool{Name: "list"}, exposed: "list"},
		{registry: drive, tool: Tool{Name: "files"}, exposed: "files"},
	}, nil)

	byNative := map[string]string{}
	for _, b := range got {
		byNative[b.registry.Name+"/"+b.tool.Name] = b.exposed
	}
	if byNative["Google/search"] != "google_search" {
		t.Fatalf("search = %q, want it unchanged", byNative["Google/search"])
	}
	if byNative["Google Drive/files"] != "google_drive_files" {
		t.Fatalf("files = %q, want it unchanged", byNative["Google Drive/files"])
	}
	googleList := byNative["Google/drive_list"]
	driveList := byNative["Google Drive/list"]
	if googleList == "google_drive_list" || driveList == "google_drive_list" || googleList == driveList {
		t.Fatalf("colliding names = %q and %q, want two distinct suffixed names", googleList, driveList)
	}
	for _, name := range []string{googleList, driveList} {
		if !strings.HasPrefix(name, "google_drive_list_") || len(name) > maxExposedNameLength {
			t.Fatalf("colliding name = %q, want google_drive_list_<digest> within %d", name, maxExposedNameLength)
		}
	}
	if googleList != disambiguateCollision("google_drive_list", google) || driveList != disambiguateCollision("google_drive_list", drive) {
		t.Fatalf("suffixes = %q and %q, want the registry digests", googleList, driveList)
	}
	// The same inputs name the tools the same way again.
	again := resolveNames([]binding{
		{registry: google, tool: Tool{Name: "drive_list"}, exposed: "drive_list"},
		{registry: drive, tool: Tool{Name: "list"}, exposed: "list"},
	}, nil)
	if again[0].exposed != googleList || again[1].exposed != driveList {
		t.Fatalf("second resolution = %q %q, want %q %q", again[0].exposed, again[1].exposed, googleList, driveList)
	}
}

// google_drive can publish list_<google's digest> next to list. The plain tool
// then spells exactly the suffixed name google's drive_list was given. That
// copy is withheld; the suffix owner keeps the name. Anything that does not
// collide is unchanged.
func TestResolveNames_PlainCopyOfSuffixIsWithheld(t *testing.T) {
	t.Parallel()
	google := mcpRegistry(t, "Google", "https://google.example/mcp")
	google.MCPTarget.Code = "com.google/mcp"
	drive := mcpRegistry(t, "Google Drive", "https://drive.example/mcp")
	drive.MCPTarget.Code = "com.google_drive/mcp"
	copy := "list_" + registryDigest(google, collisionSuffixLen)
	victim := disambiguateCollision("google_drive_list", google)

	// Drive is first, which is the order that used to make the copy win.
	got := resolveNames([]binding{
		{registry: drive, tool: Tool{Name: copy}, exposed: copy},
		{registry: drive, tool: Tool{Name: "list"}, exposed: "list"},
		{registry: drive, tool: Tool{Name: "files"}, exposed: "files"},
		{registry: google, tool: Tool{Name: "drive_list"}, exposed: "drive_list"},
		{registry: google, tool: Tool{Name: "search"}, exposed: "search"},
	}, nil)

	byNative := map[string]string{}
	for _, b := range got {
		key := b.registry.Name + "/" + b.tool.Name
		if _, dup := byNative[key]; dup {
			t.Fatalf("tool %s published twice", key)
		}
		byNative[key] = b.exposed
	}
	if _, stolen := byNative["Google Drive/"+copy]; stolen {
		t.Fatalf("copied name %q was published as %q", copy, byNative["Google Drive/"+copy])
	}
	if byNative["Google/drive_list"] != victim {
		t.Fatalf("victim = %q, want %q", byNative["Google/drive_list"], victim)
	}
	owners := 0
	for _, name := range byNative {
		if name == victim {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("bindings spelling %q = %d, want the suffix owner only", victim, owners)
	}
	if byNative["Google Drive/files"] != "google_drive_files" || byNative["Google/search"] != "google_search" {
		t.Fatalf("unchanged names = %q and %q", byNative["Google Drive/files"], byNative["Google/search"])
	}
	if byNative["Google Drive/list"] == "" || byNative["Google Drive/list"] == "google_drive_list" || byNative["Google Drive/list"] == victim {
		t.Fatalf("drive list = %q, want its own suffix", byNative["Google Drive/list"])
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

// A slug long enough that the content-hash suffix would leave the tool nothing
// used to be cut, so the exposed name no longer started with the server and
// every call answered "Unknown tool". The server part becomes a short hash of
// the slug instead. A name that still fits is not touched, and neither is a
// slug that leaves the tool one character.
func TestExposedName_OverlongSlugIsHashedNotCut(t *testing.T) {
	t.Parallel()
	slug := strings.Repeat("a", 55)
	reg := mcpRegistry(t, "Long", "https://long.example/mcp")
	reg.MCPTarget.Code = "com." + slug + "/mcp"
	if got := serverSlug(reg); got != slug {
		t.Fatalf("slug = %q, want %d a's", got, len(slug))
	}

	tool := strings.Repeat("b", 20)
	one := exposedNameFor(tool+"_one", reg).String()
	two := exposedNameFor(tool+"_two", reg).String()
	prefix := hashedSlug(slug) + "_"
	for _, name := range []string{one, two} {
		if len(name) > maxExposedNameLength {
			t.Fatalf("name %q is %d characters, want at most %d", name, len(name), maxExposedNameLength)
		}
		if !strings.HasPrefix(name, prefix) {
			t.Fatalf("name = %q, want the slug's hash %q", name, prefix)
		}
		if strings.HasPrefix(name, slug) {
			t.Fatalf("name = %q still starts with the slug, which is what the cut did", name)
		}
	}
	if one == two {
		t.Fatalf("two tools share the hashed name %q", one)
	}
	if got := registriesForExposedName([]*registrydomain.Registry{reg}, one); len(got) != 1 || got[0] != reg {
		t.Fatalf("owners of %q = %v, want the long server", one, got)
	}

	// Short enough to fit after the slug: the hash must not rename it.
	if got, want := exposedNameFor("x", reg).String(), slug+"_x"; got != want {
		t.Fatalf("short tool = %q, want %q", got, want)
	}

	// One character of tool still fits, so the server stays whole.
	barely := strings.Repeat("c", 53)
	barelyReg := mcpRegistry(t, "Barely", "https://barely.example/mcp")
	barelyReg.MCPTarget.Code = "com." + barely + "/mcp"
	longTool := strings.Repeat("d", 40)
	got := exposedNameFor(longTool, barelyReg).String()
	if !strings.HasPrefix(got, barely+"_") || len(got) > maxExposedNameLength {
		t.Fatalf("name = %q, want the 53-character server kept whole", got)
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
	if _, err := resolveAndInvoke(context.Background(), oneDown, routable(consumer, finance, analytics), namedFor(finance, "query"), nil); err != nil {
		t.Fatalf("calling the stable per-instance name: %v", err)
	}
}

func linearShelf(t *testing.T, url string) *registrydomain.Registry {
	t.Helper()
	reg := mcpRegistry(t, "Linear", url)
	reg.MCPTarget.Code = "app.linear/mcp"
	return reg
}

// storeClone is the per-install view the Store scoper builds when a principal
// holds several instances of one code: its own id, pointing back at the shelf.
func storeClone(shelf *registrydomain.Registry) *registrydomain.Registry {
	clone := *shelf
	target := *shelf.MCPTarget
	clone.MCPTarget = &target
	clone.ID = ids.New[ids.RegistryKind]()
	clone.InstanceOf = shelf.ID
	return &clone
}

// A server without URL variables gives its Store instances no config, but two
// of them installed side by side are still two instances of one code.
func TestExposedName_ConfiglessStoreInstancesStayApart(t *testing.T) {
	t.Parallel()
	a := storeClone(linearShelf(t, "https://a.linear.example/mcp"))
	b := storeClone(linearShelf(t, "https://b.linear.example/mcp"))

	nameA, nameB := namedFor(a, "save_issue"), namedFor(b, "save_issue")
	if nameA == nameB {
		t.Fatalf("two instances share the name %q", nameA)
	}
	for _, name := range []string{nameA, nameB} {
		if name == "linear_save_issue" || !strings.HasPrefix(name, "linear_") || !strings.HasSuffix(name, "_save_issue") {
			t.Fatalf("name = %q, want linear_<instance>_save_issue", name)
		}
	}
}

// Only a per-install clone takes the digest: the shelf, and the one configured
// instance that keeps the shelf's id, keep the names they already had.
func TestExposedName_ShelfAndConfiguredInstanceKeepTheirNames(t *testing.T) {
	t.Parallel()
	shelf := linearShelf(t, "https://linear.example/mcp")
	if got := namedFor(shelf, "save_issue"); got != "linear_save_issue" {
		t.Fatalf("shelf name = %q, want linear_save_issue", got)
	}

	configured := *shelf
	target := *shelf.MCPTarget
	target.InstanceConfig = map[string]string{"workspace": "acme"}
	configured.MCPTarget = &target
	configured.InstanceOf = shelf.ID
	want := "linear_" + registryDigest(shelf, 6) + "_save_issue"
	if got := namedFor(&configured, "save_issue"); got != want {
		t.Fatalf("configured instance name = %q, want %q", got, want)
	}
}

func TestComposer_ListTools_ConfiglessStoreInstancesServeDistinctNames(t *testing.T) {
	t.Parallel()
	a := storeClone(linearShelf(t, "https://a.linear.example/mcp"))
	b := storeClone(linearShelf(t, "https://b.linear.example/mcp"))
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen}}
	c := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.linear.example/mcp": {tools: tools("save_issue", "get_issue")},
		"https://b.linear.example/mcp": {tools: tools("save_issue", "get_issue")},
	}})

	got, err := c.ListTools(context.Background(), routable(consumer, a, b))
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := toolNames(got)
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, dup := seen[name]; dup {
			t.Fatalf("tools/list repeats %q: %v", name, names)
		}
		seen[name] = struct{}{}
	}
	if len(names) != 4 {
		t.Fatalf("tools = %v, want both instances' two tools", names)
	}
}
