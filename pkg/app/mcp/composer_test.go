package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type fakeUpstream struct {
	tools      []Tool
	prompts    []Prompt
	resources  []Resource
	templates  []ResourceTemplate
	listErr    error
	lastCall   string
	lastPrompt string
	lastRead   string
	result     json.RawMessage
}

func (f *fakeUpstream) ListTools(context.Context) ([]Tool, error) {
	return f.tools, f.listErr
}

func (f *fakeUpstream) CallTool(_ context.Context, name string, _ json.RawMessage) (json.RawMessage, error) {
	f.lastCall = name
	return f.result, nil
}

func (f *fakeUpstream) ListResources(context.Context) ([]Resource, error) {
	return f.resources, f.listErr
}

func (f *fakeUpstream) ListResourceTemplates(context.Context) ([]ResourceTemplate, error) {
	return f.templates, f.listErr
}

func (f *fakeUpstream) ReadResource(_ context.Context, uri string) (json.RawMessage, error) {
	if !f.SupportsResources() {
		return nil, ErrNotSupported
	}
	for _, r := range f.resources {
		if r.URI == uri {
			f.lastRead = uri
			return f.result, nil
		}
	}
	return nil, errors.New("unknown resource")
}

func (f *fakeUpstream) ListPrompts(context.Context) ([]Prompt, error) {
	return f.prompts, f.listErr
}

func (f *fakeUpstream) GetPrompt(_ context.Context, name string, _ map[string]string) (json.RawMessage, error) {
	if !f.SupportsPrompts() {
		return nil, ErrNotSupported
	}
	f.lastPrompt = name
	return f.result, nil
}

func (f *fakeUpstream) SupportsResources() bool { return len(f.resources) > 0 }
func (f *fakeUpstream) SupportsPrompts() bool   { return len(f.prompts) > 0 }

func (f *fakeUpstream) Close(context.Context) {}

type fakeDialer struct {
	upstreams map[string]*fakeUpstream
	dialErr   map[string]error
}

func (f *fakeDialer) Connect(_ context.Context, target Target) (Upstream, error) {
	if err := f.dialErr[target.URL]; err != nil {
		return nil, err
	}
	up, ok := f.upstreams[target.URL]
	if !ok {
		return nil, errors.New("unknown target")
	}
	return up, nil
}

func mcpRegistry(t *testing.T, name, url string) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(
		ids.New[ids.GatewayKind](), name, "", 0,
		&registrydomain.MCPTarget{URL: url},
	)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return reg
}

func routable(consumer *consumerdomain.Consumer, registries ...*registrydomain.Registry) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{Consumer: consumer, Registries: registries}
}

type mapCache struct{ m map[string]any }

func newMapCache() *mapCache { return &mapCache{m: map[string]any{}} }

func (c *mapCache) Get(key string) (any, bool) {
	v, ok := c.m[key]
	return v, ok
}

func (c *mapCache) Set(key string, value any) { c.m[key] = value }

func newTestComposer(dialer Dialer) Composer {
	return NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))
}

func tools(names ...string) []Tool {
	out := make([]Tool, 0, len(names))
	for _, n := range names {
		out = append(out, Tool{Name: n})
	}
	return out
}

func toolNames(ts []Tool) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestComposer_ListTools_EmptyToolkitExposesAll(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("create_issue", "list_repos")},
	}}
	c := newTestComposer(dialer)

	got, err := c.ListTools(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"create_issue", "list_repos"}
	if names := toolNames(got); len(names) != 2 || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("tools = %v, want %v", names, want)
	}
}

func TestComposer_ListTools_PresentButEmptyToolkitDeniesAll(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("create_issue", "list_repos")},
	}}
	c := newTestComposer(dialer)

	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}},
	}
	got, err := c.ListTools(context.Background(), routable(consumer, regA))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("tools = %v, want none: toolkit [] must mean deny-all, not allow-all", toolNames(got))
	}
}

func TestComposer_ListTools_ToolkitSelectAndRename(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("create_issue", "list_repos", "delete_repo")},
	}}
	c := newTestComposer(dialer)

	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: regA.ID, Tool: "create_issue", ExposeAs: "gh_create_issue"},
			{RegistryID: regA.ID, Tool: "list_repos"},
		}},
	}
	got, err := c.ListTools(context.Background(), routable(consumer, regA))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := toolNames(got)
	if len(names) != 2 || names[0] != "gh_create_issue" || names[1] != "list_repos" {
		t.Fatalf("tools = %v, want [gh_create_issue list_repos]", names)
	}
}

func TestComposer_ListTools_CollisionAutoPrefix(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("search")},
		"https://b.example.com/mcp": {tools: tools("search")},
	}}
	c := newTestComposer(dialer)

	got, err := c.ListTools(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := toolNames(got)
	if len(names) != 2 || names[0] != "github_search" || names[1] != "slack_search" {
		t.Fatalf("tools = %v, want [github_search slack_search]", names)
	}
}

func TestComposer_FailMode(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "up", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "down", "https://b.example.com/mcp")
	dialer := &fakeDialer{
		upstreams: map[string]*fakeUpstream{
			"https://a.example.com/mcp": {tools: tools("alive")},
		},
		dialErr: map[string]error{
			"https://b.example.com/mcp": ErrUnreachable,
		},
	}
	c := newTestComposer(dialer)

	t.Run("closed rejects", func(t *testing.T) {
		t.Parallel()
		consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeClosed}}
		_, err := c.ListTools(context.Background(), routable(consumer, regA, regB))
		if !errors.Is(err, ErrUpstreamUnavailable) {
			t.Fatalf("error = %v, want ErrUpstreamUnavailable", err)
		}
	})

	t.Run("open serves reachable", func(t *testing.T) {
		t.Parallel()
		consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen}}
		got, err := c.ListTools(context.Background(), routable(consumer, regA, regB))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if names := toolNames(got); len(names) != 1 || names[0] != "alive" {
			t.Fatalf("tools = %v, want [alive]", names)
		}
	})
}

func TestComposer_CallTool_RoutesToOwningUpstream(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	upA := &fakeUpstream{tools: tools("search"), result: json.RawMessage(`{"content":[]}`)}
	upB := &fakeUpstream{tools: tools("search"), result: json.RawMessage(`{"content":[]}`)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": upA,
		"https://b.example.com/mcp": upB,
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB)

	res, err := c.CallTool(context.Background(), rc, "slack_search", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res) != `{"content":[]}` {
		t.Fatalf("result = %s", res)
	}
	if upB.lastCall != "search" {
		t.Fatalf("upstream call = %q, want search on slack upstream", upB.lastCall)
	}
	if upA.lastCall != "" {
		t.Fatalf("github upstream was called: %q", upA.lastCall)
	}

	if _, err := c.CallTool(context.Background(), rc, "missing_tool", nil); !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
}

func TestComposer_NoMCPRegistries(t *testing.T) {
	t.Parallel()
	c := newTestComposer(&fakeDialer{})
	_, err := c.ListTools(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}))
	if !errors.Is(err, ErrNoMCPRegistries) {
		t.Fatalf("error = %v, want ErrNoMCPRegistries", err)
	}
}

func prompts(names ...string) []Prompt {
	out := make([]Prompt, 0, len(names))
	for _, n := range names {
		out = append(out, Prompt{Name: n})
	}
	return out
}

func TestComposer_ListPrompts_MergesAndPrefixesCollisions(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {prompts: prompts("summarize", "triage")},
		"https://b.example.com/mcp": {prompts: prompts("summarize")},
	}}
	c := newTestComposer(dialer)

	got, err := c.ListPrompts(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := make([]string, 0, len(got))
	for _, p := range got {
		names = append(names, p.Name)
	}
	want := []string{"github_summarize", "triage", "slack_summarize"}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("prompts = %v, want %v", names, want)
	}
}

func TestComposer_GetPrompt_RoutesToOwningUpstream(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	upA := &fakeUpstream{prompts: prompts("summarize"), result: json.RawMessage(`{"messages":[]}`)}
	upB := &fakeUpstream{prompts: prompts("summarize"), result: json.RawMessage(`{"messages":[]}`)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": upA,
		"https://b.example.com/mcp": upB,
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB)

	res, err := c.GetPrompt(context.Background(), rc, "slack_summarize", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res) != `{"messages":[]}` {
		t.Fatalf("result = %s", res)
	}
	if upB.lastPrompt != "summarize" || upA.lastPrompt != "" {
		t.Fatalf("prompt routed to wrong upstream: a=%q b=%q", upA.lastPrompt, upB.lastPrompt)
	}

	if _, err := c.GetPrompt(context.Background(), rc, "missing", nil); !errors.Is(err, ErrPromptNotFound) {
		t.Fatalf("error = %v, want ErrPromptNotFound", err)
	}
}

func TestComposer_ListResources_MergesUpstreams(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {resources: []Resource{{URI: "repo://a", Name: "a"}}},
		"https://b.example.com/mcp": {resources: []Resource{{URI: "chan://b", Name: "b"}}},
	}}
	c := newTestComposer(dialer)

	got, err := c.ListResources(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0].URI != "repo://a" || got[1].URI != "chan://b" {
		t.Fatalf("resources = %+v", got)
	}
}

func TestComposer_Toolkit_GovernsAllSurfaces(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	upA := &fakeUpstream{
		tools:     tools("create_issue", "delete_repo"),
		prompts:   prompts("summarize", "triage"),
		resources: []Resource{{URI: "repo://github/readme"}, {URI: "secret://keys"}},
		templates: []ResourceTemplate{{Name: "files", URITemplate: "repo://github/{path}"}},
		result:    json.RawMessage(`{"contents":[]}`),
	}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": upA}}
	c := newTestComposer(dialer)

	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: regA.ID, Tool: "create_issue"},
			{RegistryID: regA.ID, Prompt: "summarize", ExposeAs: "gh_summarize"},
			{RegistryID: regA.ID, Resource: "repo://github/*"},
		}},
	}
	rc := routable(consumer, regA)

	gotTools, err := c.ListTools(context.Background(), rc)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(gotTools) != 1 || gotTools[0].Name != "create_issue" {
		t.Fatalf("tools = %v, want only create_issue", toolNames(gotTools))
	}

	gotPrompts, err := c.ListPrompts(context.Background(), rc)
	if err != nil {
		t.Fatalf("list prompts: %v", err)
	}
	if len(gotPrompts) != 1 || gotPrompts[0].Name != "gh_summarize" {
		t.Fatalf("prompts = %+v, want only gh_summarize", gotPrompts)
	}
	if _, err := c.GetPrompt(context.Background(), rc, "gh_summarize", nil); err != nil {
		t.Fatalf("get renamed prompt: %v", err)
	}
	if upA.lastPrompt != "summarize" {
		t.Fatalf("upstream prompt = %q, want summarize", upA.lastPrompt)
	}
	if _, err := c.GetPrompt(context.Background(), rc, "triage", nil); !errors.Is(err, ErrPromptNotFound) {
		t.Fatalf("unlisted prompt error = %v, want ErrPromptNotFound", err)
	}

	gotResources, err := c.ListResources(context.Background(), rc)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(gotResources) != 1 || gotResources[0].URI != "repo://github/readme" {
		t.Fatalf("resources = %+v, want only repo://github/readme", gotResources)
	}
	if _, err := c.ReadResource(context.Background(), rc, "repo://github/readme"); err != nil {
		t.Fatalf("read allowed resource: %v", err)
	}
	if _, err := c.ReadResource(context.Background(), rc, "secret://keys"); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("denied resource error = %v, want ErrResourceNotFound", err)
	}

	gotTemplates, err := c.ListResourceTemplates(context.Background(), rc)
	if err != nil {
		t.Fatalf("list templates: %v", err)
	}
	if len(gotTemplates) != 1 {
		t.Fatalf("templates = %+v, want the registry's templates (it has resource entries)", gotTemplates)
	}
}

func TestComposer_Toolkit_ToolOnlyEntriesHidePromptsAndResources(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	upA := &fakeUpstream{
		tools:     tools("create_issue"),
		prompts:   prompts("summarize"),
		resources: []Resource{{URI: "repo://github/readme"}},
		templates: []ResourceTemplate{{Name: "files", URITemplate: "repo://github/{path}"}},
		result:    json.RawMessage(`{"contents":[]}`),
	}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": upA}}
	c := newTestComposer(dialer)

	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{{RegistryID: regA.ID, Tool: consumerdomain.ToolWildcard}}},
	}
	rc := routable(consumer, regA)

	gotPrompts, err := c.ListPrompts(context.Background(), rc)
	if err != nil {
		t.Fatalf("list prompts: %v", err)
	}
	if len(gotPrompts) != 0 {
		t.Fatalf("prompts = %+v, want none without prompt entries", gotPrompts)
	}
	gotResources, err := c.ListResources(context.Background(), rc)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(gotResources) != 0 {
		t.Fatalf("resources = %+v, want none without resource entries", gotResources)
	}
	gotTemplates, err := c.ListResourceTemplates(context.Background(), rc)
	if err != nil {
		t.Fatalf("list templates: %v", err)
	}
	if len(gotTemplates) != 0 {
		t.Fatalf("templates = %+v, want none without resource entries", gotTemplates)
	}
	if _, err := c.ReadResource(context.Background(), rc, "repo://github/readme"); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("read error = %v, want ErrResourceNotFound", err)
	}
}

func TestComposer_ReadResource_RoutesByURI(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	upA := &fakeUpstream{resources: []Resource{{URI: "repo://a"}}, result: json.RawMessage(`{"contents":[]}`)}
	upB := &fakeUpstream{resources: []Resource{{URI: "chan://b"}}, result: json.RawMessage(`{"contents":[]}`)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": upA,
		"https://b.example.com/mcp": upB,
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB)

	if _, err := c.ReadResource(context.Background(), rc, "chan://b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if upB.lastRead != "chan://b" || upA.lastRead != "" {
		t.Fatalf("read routed to wrong upstream: a=%q b=%q", upA.lastRead, upB.lastRead)
	}
}
