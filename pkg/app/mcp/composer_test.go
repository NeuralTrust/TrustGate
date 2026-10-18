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
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
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

type fakeCreds struct {
	err error
	// errByURL optionally returns a per-upstream error keyed by MCPTarget.URL.
	errByURL map[string]error
	mu       sync.Mutex
	applied  []string
	// minted records consent errors returned outside a resolve probe. A probe
	// must not count: that is the connect ticket the probe exists to avoid.
	minted []string
}

func (f *fakeCreds) Apply(ctx context.Context, _ *appconsumer.RoutableConsumer, reg *registrydomain.Registry, _ *Target) error {
	decided := f.err
	url := ""
	if reg != nil && reg.MCPTarget != nil {
		url = reg.MCPTarget.URL
		if f.errByURL != nil {
			if err, ok := f.errByURL[url]; ok {
				decided = err
			}
		}
	}
	if url != "" {
		f.mu.Lock()
		f.applied = append(f.applied, url)
		var consent *ConsentRequiredError
		if !resolveProbe(ctx) && errors.As(decided, &consent) {
			f.minted = append(f.minted, url)
		}
		f.mu.Unlock()
	}
	return decided
}

func (f *fakeCreds) appliedURLs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.applied))
	copy(out, f.applied)
	return out
}

func (f *fakeCreds) mintedURLs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.minted))
	copy(out, f.minted)
	return out
}

func mcpRegistry(t *testing.T, name, url string) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(
		ids.New[ids.GatewayKind](), name, "",
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

type mapCache struct {
	mu sync.Mutex
	m  map[string]any
}

func newMapCache() *mapCache { return &mapCache{m: map[string]any{}} }

func (c *mapCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}

func (c *mapCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = value
}

func (c *mapCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func newTestComposer(dialer Dialer) Composer {
	return NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler))
}

func resolveAndInvoke(
	ctx context.Context,
	c Composer,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	target, err := c.Resolve(ctx, rc, name)
	if err != nil {
		return nil, err
	}
	return c.Invoke(ctx, rc, target, arguments)
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
	want := []string{namedFor(regA, "create_issue"), namedFor(regA, "list_repos")}
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
	want := []string{namedFor(regA, "gh_create_issue"), namedFor(regA, "list_repos")}
	if len(names) != 2 || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("tools = %v, want %v", names, want)
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
	if len(names) != 2 || names[0] != namedFor(regA, "search") || names[1] != namedFor(regB, "search") {
		t.Fatalf("tools = %v, want [%s %s]", names, namedFor(regA, "search"), namedFor(regB, "search"))
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
		if names := toolNames(got); len(names) != 1 || names[0] != namedFor(regA, "alive") {
			t.Fatalf("tools = %v, want [%s]", names, namedFor(regA, "alive"))
		}
	})
}

func TestComposer_ConsentRequiredWhenAllNeedConsent(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "coda", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("x")},
	}}
	creds := &fakeCreds{err: &ConsentRequiredError{Provider: "coda", Ticket: "tk", Path: "/p/mcp"}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))

	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen}}
	_, err := c.ListTools(context.Background(), routable(consumer, regA))
	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatalf("error = %v, want ConsentRequiredError when every upstream needs consent", err)
	}
}

func TestComposer_PartialConsentServesLinkedUpstream(t *testing.T) {
	t.Parallel()
	regLinked := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	regPending := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {tools: tools("search")},
		"https://notion.example.com/mcp": {tools: tools("query")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{
			Provider: "com.notion/mcp",
			Ticket:   "tk",
			Path:     "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))

	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeClosed}}
	got, err := c.ListTools(context.Background(), routable(consumer, regLinked, regPending))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if names := toolNames(got); len(names) != 1 || names[0] != namedFor(regLinked, "search") {
		t.Fatalf("tools = %v, want [%s] from the linked upstream only", names, namedFor(regLinked, "search"))
	}
}

func TestComposer_ResolveThenInvoke_RoutesToOwningUpstream(t *testing.T) {
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

	res, err := resolveAndInvoke(context.Background(), c, rc, namedFor(regB, "search"), nil)
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

	if _, err := c.Resolve(context.Background(), rc, "missing_tool"); !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
}

// A tool served by a healthy upstream must still be callable while a different
// upstream awaits user consent: an unconnected Notion must not break a call
// routed to another MCP server.
func TestComposer_Resolve_UnrelatedConsentDoesNotBlockOtherUpstream(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	graphite := mcpRegistry(t, "graphite", "https://graphite.example.com/mcp")
	upGraphite := &fakeUpstream{tools: tools("list_diffs"), result: json.RawMessage(`{"content":[]}`)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp":   {tools: tools("search")},
		"https://graphite.example.com/mcp": upGraphite,
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{
			Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen},
	}, notion, graphite)

	res, err := resolveAndInvoke(context.Background(), c, rc, namedFor(graphite, "list_diffs"), nil)
	if err != nil {
		t.Fatalf("call routed to a healthy upstream must succeed, got %v", err)
	}
	if string(res) != `{"content":[]}` {
		t.Fatalf("result = %s", res)
	}
	if upGraphite.lastCall != "list_diffs" {
		t.Fatalf("upstream call = %q, want list_diffs", upGraphite.lastCall)
	}
}

// A tool the upstream offers but the toolkit excludes is a policy denial: it
// must answer 403 rather than "not found", and never an authorization prompt —
// connecting an account cannot grant a tool the consumer is not allowed to use.
func TestComposer_Resolve_ToolkitDeniedIsForbidden(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	up := &fakeUpstream{
		tools:  tools("notion-create-pages", "notion-search"),
		result: json.RawMessage(`{"content":[]}`),
	}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://notion.example.com/mcp": up}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: notion.ID, Tool: "notion-create-pages"},
		}},
	}, notion)

	target, err := c.Resolve(context.Background(), rc, "notion-search")
	var denied *ToolNotPermittedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want ToolNotPermittedError", err)
	}
	if denied.Tool != "notion-search" {
		t.Fatalf("tool = %q, want notion-search", denied.Tool)
	}
	if target != nil {
		t.Fatalf("target = %+v, want nil so nothing can be invoked", target)
	}
	if up.lastCall != "" {
		t.Fatalf("upstream was invoked with %q for a denied tool", up.lastCall)
	}
}

// Resolve binds the exposed name to the upstream that serves it and hands back
// both names, without dialing the tool: the binding is fixed before any plugin
// gets to see the request.
func TestComposer_Resolve_RoutesToOwningUpstream(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	upA := &fakeUpstream{tools: tools("search")}
	upB := &fakeUpstream{tools: tools("search")}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": upA,
		"https://b.example.com/mcp": upB,
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB)

	exposed := namedFor(regB, "search")
	target, err := c.Resolve(context.Background(), rc, exposed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Registry != regB {
		t.Fatalf("registry = %v, want slack", target.Registry)
	}
	if target.Tool.Name != "search" {
		t.Fatalf("native tool = %q, want search", target.Tool.Name)
	}
	if target.Exposed != exposed {
		t.Fatalf("exposed = %q, want %q", target.Exposed, exposed)
	}
	if upA.lastCall != "" || upB.lastCall != "" {
		t.Fatalf("Resolve must not invoke any upstream: a=%q b=%q", upA.lastCall, upB.lastCall)
	}
}

func TestComposer_Resolve_UnknownToolStaysNotFound(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp": {tools: tools("notion-create-pages")},
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: notion.ID, Tool: "notion-create-pages"},
		}},
	}, notion)

	target, err := c.Resolve(context.Background(), rc, "does-not-exist")
	if !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("error = %v, want ErrToolNotFound", err)
	}
	if target != nil {
		t.Fatalf("target = %+v, want nil on error", target)
	}
}

// A toolkit denial outranks a pending consent elsewhere: the tool is forbidden
// whether or not the user connects anything.
func TestComposer_Resolve_DeniedBeatsPendingConsent(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	linear := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp": {tools: tools("notion-create-pages", "notion-search")},
		"https://linear.example.com/mcp": {tools: tools("linear-search")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://linear.example.com/mcp": &ConsentRequiredError{
			Provider: "app.linear/mcp", Ticket: "tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{
			FailMode: consumerdomain.FailModeOpen,
			Toolkit: consumerdomain.Toolkit{
				{RegistryID: notion.ID, Tool: "notion-create-pages"},
				{RegistryID: linear.ID, Tool: consumerdomain.ToolWildcard},
			},
		},
	}, notion, linear)

	_, err := c.Resolve(context.Background(), rc, namedFor(notion, "notion-search"))
	var consent *ConsentRequiredError
	if errors.As(err, &consent) {
		t.Fatal("a forbidden tool must not send the user through a consent flow")
	}
	var denied *ToolNotPermittedError
	if !errors.As(err, &denied) {
		t.Fatalf("error = %v, want a policy denial", err)
	}
	if denied.Tool != namedFor(notion, "notion-search") {
		t.Fatalf("denied tool = %q, want the exposed name", denied.Tool)
	}
}

// A tool no reachable upstream exposes, while another awaits consent, reports
// the consent requirement: it may well live behind the unconnected provider.
func TestComposer_Resolve_UnknownToolSurfacesPendingConsent(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	graphite := mcpRegistry(t, "graphite", "https://graphite.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp":   {tools: tools("search")},
		"https://graphite.example.com/mcp": {tools: tools("list_diffs")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{
			Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen},
	}, notion, graphite)

	_, err := c.Resolve(context.Background(), rc, namedFor(notion, "search"))
	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatalf("error = %v, want ConsentRequiredError for the unconnected provider", err)
	}
	if consentErr.Provider != "com.notion/mcp" {
		t.Fatalf("provider = %q, want com.notion/mcp", consentErr.Provider)
	}
}

// An unknown name is not hiding on whichever installed server lacks a
// credential. Resolving it must answer -32602's tool error and must not enter
// that server's consent flow, which is what mints a connect ticket (ENG-2178).
func TestComposer_Resolve_UnknownNameDoesNotConsentAnotherServer(t *testing.T) {
	t.Parallel()
	atlassian := mcpRegistry(t, "Atlassian", "https://atlassian.example.com/mcp")
	atlassian.MCPTarget.Code = "com.atlassian/mcp"
	graphite := mcpRegistry(t, "Graphite", "https://graphite.example.com/mcp")
	graphite.MCPTarget.Code = "com.graphite/mcp"
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://atlassian.example.com/mcp": {tools: tools("searchJira")},
		"https://graphite.example.com/mcp":  {tools: tools("list_diffs")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://atlassian.example.com/mcp": &ConsentRequiredError{
			Provider: "com.atlassian/mcp", Ticket: "tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen},
	}, atlassian, graphite)

	_, err := c.Resolve(context.Background(), rc, "does-not-exist")
	var unknown *UnknownToolError
	if !errors.As(err, &unknown) {
		t.Fatalf("error = %v, want UnknownToolError", err)
	}
	if unknown.Error() != "Unknown tool: does-not-exist" {
		t.Fatalf("error = %q, want the unknown-tool message", unknown.Error())
	}
	if !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("error = %v, want it to be ErrToolNotFound so the handler answers -32602", err)
	}
	var consent *ConsentRequiredError
	if errors.As(err, &consent) {
		t.Fatalf("unknown name returned a consent error for %q", consent.Provider)
	}
	if minted := creds.mintedURLs(); len(minted) != 0 {
		t.Fatalf("connect tickets minted for %v", minted)
	}
}

// A tool of an unconnected server still asks that server's user to connect.
// A second unconnected server must not be the one named, and must not have a
// ticket minted for it.
func TestComposer_Resolve_UnconnectedToolConsentsItsOwner(t *testing.T) {
	t.Parallel()
	notion := mcpRegistry(t, "Notion", "https://notion.example.com/mcp")
	notion.MCPTarget.Code = "com.notion/mcp"
	atlassian := mcpRegistry(t, "Atlassian", "https://atlassian.example.com/mcp")
	atlassian.MCPTarget.Code = "com.atlassian/mcp"
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp":    {tools: tools("search")},
		"https://atlassian.example.com/mcp": {tools: tools("searchJira")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{
			Provider: "com.notion/mcp", Ticket: "notion-tk", Path: "/p/mcp",
		},
		"https://atlassian.example.com/mcp": &ConsentRequiredError{
			Provider: "com.atlassian/mcp", Ticket: "atl-tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen},
	}, notion, atlassian)

	_, err := c.Resolve(context.Background(), rc, namedFor(atlassian, "searchJira"))
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) {
		t.Fatalf("error = %v, want ConsentRequiredError for Atlassian", err)
	}
	if consent.Provider != "com.atlassian/mcp" {
		t.Fatalf("provider = %q, want com.atlassian/mcp", consent.Provider)
	}
	if consent.Ticket != "atl-tk" {
		t.Fatalf("ticket = %q, want the Atlassian consent, not another server's", consent.Ticket)
	}
	applied := creds.appliedURLs()
	if len(applied) != 1 || applied[0] != atlassian.MCPTarget.URL {
		t.Fatalf("credential checks = %v, want only Atlassian", applied)
	}
}

// A tool of a server that is installed but unreachable names that server and
// its state. It must not come back as another server's consent prompt.
func TestComposer_Resolve_UnavailableOwnerNamesThatServer(t *testing.T) {
	t.Parallel()
	linear := mcpRegistry(t, "Linear", "https://linear.example.com/mcp")
	linear.MCPTarget.Code = "com.linear/mcp"
	graphite := mcpRegistry(t, "Graphite", "https://graphite.example.com/mcp")
	graphite.MCPTarget.Code = "com.graphite/mcp"
	atlassian := mcpRegistry(t, "Atlassian", "https://atlassian.example.com/mcp")
	atlassian.MCPTarget.Code = "com.atlassian/mcp"
	dialer := &fakeDialer{
		upstreams: map[string]*fakeUpstream{
			"https://linear.example.com/mcp":    {tools: tools("list_issues")},
			"https://graphite.example.com/mcp":  {tools: tools("list_diffs")},
			"https://atlassian.example.com/mcp": {tools: tools("searchJira")},
		},
		dialErr: map[string]error{
			"https://graphite.example.com/mcp": ErrUnreachable,
		},
	}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://atlassian.example.com/mcp": &ConsentRequiredError{
			Provider: "com.atlassian/mcp", Ticket: "tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen},
	}, linear, graphite, atlassian)

	_, err := c.Resolve(context.Background(), rc, namedFor(graphite, "list_diffs"))
	var consent *ConsentRequiredError
	if errors.As(err, &consent) {
		t.Fatalf("unavailable tool returned consent for %q", consent.Provider)
	}
	var down *ServerNotServingError
	if !errors.As(err, &down) {
		t.Fatalf("error = %v, want ServerNotServingError", err)
	}
	if down.Server != "Graphite" || down.State != InventoryStateUnavailable {
		t.Fatalf("error = %+v, want Graphite unavailable", down)
	}
	if strings.Contains(err.Error(), "atlassian") || strings.Contains(err.Error(), "Atlassian") {
		t.Fatalf("error = %q names the wrong server", err.Error())
	}
	for _, url := range creds.appliedURLs() {
		if url == atlassian.MCPTarget.URL {
			t.Fatal("resolving Graphite's tool minted a connect attempt for Atlassian")
		}
	}
}

// tools/list on a fail-closed consumer still refuses when any upstream is down
// (TestComposer_FailMode). Resolving a name does not use another registry's
// discovery or consent error as the answer, which is also what used to mint a
// connect ticket for a server the call does not target.
func TestComposer_Resolve_FailClosedIgnoresUnrelatedUpstream(t *testing.T) {
	t.Parallel()
	linear := mcpRegistry(t, "Linear", "https://linear.example.com/mcp")
	linear.MCPTarget.Code = "com.linear/mcp"
	graphite := mcpRegistry(t, "Graphite", "https://graphite.example.com/mcp")
	graphite.MCPTarget.Code = "com.graphite/mcp"
	atlassian := mcpRegistry(t, "Atlassian", "https://atlassian.example.com/mcp")
	atlassian.MCPTarget.Code = "com.atlassian/mcp"
	up := &fakeUpstream{tools: tools("list_issues"), result: json.RawMessage(`{"content":[]}`)}
	dialer := &fakeDialer{
		upstreams: map[string]*fakeUpstream{
			"https://linear.example.com/mcp":    up,
			"https://graphite.example.com/mcp":  {tools: tools("list_diffs")},
			"https://atlassian.example.com/mcp": {tools: tools("searchJira")},
		},
		dialErr: map[string]error{
			"https://graphite.example.com/mcp": ErrUnreachable,
		},
	}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://atlassian.example.com/mcp": &ConsentRequiredError{
			Provider: "com.atlassian/mcp", Ticket: "tk", Path: "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP:  &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeClosed},
	}, linear, graphite, atlassian)

	if _, err := resolveAndInvoke(context.Background(), c, rc, namedFor(linear, "list_issues"), nil); err != nil {
		t.Fatalf("call to the healthy owner = %v, want it to ignore the other servers", err)
	}
	if up.lastCall != "list_issues" {
		t.Fatalf("upstream call = %q, want list_issues", up.lastCall)
	}
	for _, url := range creds.appliedURLs() {
		if url == atlassian.MCPTarget.URL || url == graphite.MCPTarget.URL {
			t.Fatalf("calling Linear dialed %s", url)
		}
	}
}

// Invoke dials the registry the target names and calls the tool by its native
// name, whatever the exposed name was: a rewritten name can never reroute.
func TestComposer_Invoke_UsesResolvedTarget(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	regB := mcpRegistry(t, "slack", "https://b.example.com/mcp")
	upA := &fakeUpstream{tools: tools("search"), result: json.RawMessage(`{"content":["a"]}`)}
	upB := &fakeUpstream{tools: tools("search"), result: json.RawMessage(`{"content":["b"]}`)}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": upA,
		"https://b.example.com/mcp": upB,
	}}
	c := newTestComposer(dialer)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA, regB)

	target := &ResolvedTool{Registry: regB, Tool: Tool{Name: "search"}, Exposed: "whatever_the_caller_said"}
	res, err := c.Invoke(context.Background(), rc, target, json.RawMessage(`{"q":"x"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res) != `{"content":["b"]}` {
		t.Fatalf("result = %s, want the slack upstream's answer", res)
	}
	if upB.lastCall != "search" {
		t.Fatalf("upstream call = %q, want search on slack upstream", upB.lastCall)
	}
	if upA.lastCall != "" {
		t.Fatalf("github upstream was called: %q", upA.lastCall)
	}

	if _, err := c.Invoke(context.Background(), rc, nil, nil); !errors.Is(err, ErrToolNotFound) {
		t.Fatalf("nil target error = %v, want ErrToolNotFound", err)
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
	want := []string{namedFor(regA, "summarize"), namedFor(regA, "triage"), namedFor(regB, "summarize")}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("prompts = %v, want %v", names, want)
	}
}

func TestComposer_ListPrompts_WildcardDoesNotShadowExposeAs(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {prompts: prompts("summarize", "triage")},
	}}
	c := newTestComposer(dialer)

	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: regA.ID, Prompt: consumerdomain.ToolWildcard},
			{RegistryID: regA.ID, Prompt: "summarize", ExposeAs: "gh_summarize"},
		}},
	}
	got, err := c.ListPrompts(context.Background(), routable(consumer, regA))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := make(map[string]struct{}, len(got))
	for _, p := range got {
		names[p.Name] = struct{}{}
	}
	if _, ok := names[namedFor(regA, "gh_summarize")]; !ok {
		t.Fatalf("prompts = %v, want the expose_as alias gh_summarize to win over the wildcard", names)
	}
	if _, ok := names[namedFor(regA, "summarize")]; ok {
		t.Fatalf("prompts = %v, raw summarize must not leak when an alias is configured", names)
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

	res, err := c.GetPrompt(context.Background(), rc, namedFor(regB, "summarize"), nil)
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
	if len(gotTools) != 1 || gotTools[0].Name != namedFor(regA, "create_issue") {
		t.Fatalf("tools = %v, want only create_issue", toolNames(gotTools))
	}

	gotPrompts, err := c.ListPrompts(context.Background(), rc)
	if err != nil {
		t.Fatalf("list prompts: %v", err)
	}
	if len(gotPrompts) != 1 || gotPrompts[0].Name != namedFor(regA, "gh_summarize") {
		t.Fatalf("prompts = %+v, want only gh_summarize", gotPrompts)
	}
	if _, err := c.GetPrompt(context.Background(), rc, namedFor(regA, "gh_summarize"), nil); err != nil {
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

// A consumer with no MCP policy (fail mode unset) must degrade the same way
// for prompts as it does for tools: an upstream still awaiting consent is
// skipped, and prompts from the linked upstreams are served. This is exactly
// the virtual-MCP-with-optional-providers setup, where a hard failure here
// makes clients abort their whole surface refresh.
func TestComposer_ListPrompts_PartialConsentServesLinkedUpstream(t *testing.T) {
	t.Parallel()
	regLinked := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	regPending := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {prompts: prompts("triage")},
		"https://notion.example.com/mcp": {prompts: prompts("summarize")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{
			Provider: "com.notion/mcp",
			Ticket:   "tk",
			Path:     "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))

	for _, consumer := range []*consumerdomain.Consumer{
		{Type: consumerdomain.TypeMCP},
		{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeClosed}},
	} {
		got, err := c.ListPrompts(context.Background(), routable(consumer, regLinked, regPending))
		if err != nil {
			t.Fatalf("unexpected error (fail mode %q): %v", consumer.FailMode(), err)
		}
		names := make([]string, 0, len(got))
		for _, p := range got {
			names = append(names, p.Name)
		}
		if len(names) != 1 || names[0] != namedFor(regLinked, "triage") {
			t.Fatalf("prompts = %v, want [%s] from the linked upstream only", names, namedFor(regLinked, "triage"))
		}
	}
}

func TestComposer_ListPrompts_ConsentRequiredWhenAllNeedConsent(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "coda", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {prompts: prompts("x")},
	}}
	creds := &fakeCreds{err: &ConsentRequiredError{Provider: "coda", Ticket: "tk", Path: "/p/mcp"}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))

	_, err := c.ListPrompts(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regA))
	var consentErr *ConsentRequiredError
	if !errors.As(err, &consentErr) {
		t.Fatalf("error = %v, want ConsentRequiredError when every upstream needs consent", err)
	}
}

// A prompt no reachable upstream serves may live behind the upstream that is
// still awaiting consent, so the consent requirement is the useful answer —
// mirroring CallTool.
func TestComposer_GetPrompt_UnknownPromptSurfacesPendingConsent(t *testing.T) {
	t.Parallel()
	regLinked := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	regPending := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {prompts: prompts("triage")},
		"https://notion.example.com/mcp": {prompts: prompts("summarize")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ConsentRequiredError{
			Provider: "com.notion/mcp",
			Ticket:   "tk",
			Path:     "/p/mcp",
		},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regLinked, regPending)

	var consentErr *ConsentRequiredError
	if _, err := c.GetPrompt(context.Background(), rc, namedFor(regPending, "summarize"), nil); !errors.As(err, &consentErr) {
		t.Fatalf("error = %v, want ConsentRequiredError for the unconnected provider", err)
	}
	if consentErr.Provider != "com.notion/mcp" {
		t.Fatalf("provider = %q, want com.notion/mcp", consentErr.Provider)
	}
	if _, err := c.GetPrompt(context.Background(), rc, namedFor(regLinked, "triage"), nil); err != nil {
		t.Fatalf("prompt on the linked upstream must still resolve: %v", err)
	}
}

// A server with no account for this caller is waiting on someone, not broken.
// Taken for an unreachable upstream, it failed the whole surface of a consumer
// that fails closed, and a call to one of its tools answered "tool not found"
// instead of saying whose account is missing.
func TestComposer_ApplicationNotConnectedIsSkippedLikeAPendingConsent(t *testing.T) {
	t.Parallel()
	regLinked := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	regPerUser := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {tools: tools("search")},
		"https://notion.example.com/mcp": {tools: tools("query")},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ApplicationNotConnectedError{Provider: "com.notion/mcp", Registry: "notion"},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeClosed}}
	rc := routable(consumer, regLinked, regPerUser)

	got, err := c.ListTools(context.Background(), rc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if names := toolNames(got); len(names) != 1 || names[0] != namedFor(regLinked, "search") {
		t.Fatalf("tools = %v, want [%s] from the connected upstream only", names, namedFor(regLinked, "search"))
	}

	_, err = c.Resolve(context.Background(), rc, namedFor(regPerUser, "query"))
	var notConnected *ApplicationNotConnectedError
	if !errors.As(err, &notConnected) || notConnected.Provider != "com.notion/mcp" {
		t.Fatalf("error = %v, want ApplicationNotConnectedError for notion", err)
	}
}

func TestComposer_ApplicationNotConnectedWhenNoUpstreamHasAnAccount(t *testing.T) {
	t.Parallel()
	regShared := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {tools: tools("search")},
	}}
	creds := &fakeCreds{err: &ApplicationNotConnectedError{Provider: "linear", Registry: "linear", Shared: true}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))

	_, err := c.ListTools(context.Background(), routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, regShared))
	var notConnected *ApplicationNotConnectedError
	if !errors.As(err, &notConnected) || !notConnected.Shared {
		t.Fatalf("error = %v, want the shared ApplicationNotConnectedError", err)
	}
	if errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("error = %v reads as an unreachable upstream", err)
	}
}

// Prompts and resources are the same surface as tools, so a server with no
// account for this caller is skipped there too, even by a consumer that fails
// closed: a client listing everything after initialize must not fail on prompts
// what it no longer fails on tools (ENG-1787).
func TestComposer_ApplicationNotConnectedIsSkippedForPromptsAndResources(t *testing.T) {
	t.Parallel()
	regLinked := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	regPerUser := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://linear.example.com/mcp": {prompts: prompts("triage"), resources: []Resource{{URI: "linear://issues"}}},
		"https://notion.example.com/mcp": {prompts: prompts("summarize"), resources: []Resource{{URI: "notion://pages"}}},
	}}
	creds := &fakeCreds{errByURL: map[string]error{
		"https://notion.example.com/mcp": &ApplicationNotConnectedError{Provider: "com.notion/mcp", Registry: "notion"},
	}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeClosed}}
	rc := routable(consumer, regLinked, regPerUser)

	listed, err := c.ListPrompts(context.Background(), rc)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != namedFor(regLinked, "triage") {
		t.Fatalf("prompts = %v, want only the connected upstream's", listed)
	}
	resources, err := c.ListResources(context.Background(), rc)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(resources) != 1 || resources[0].URI != "linear://issues" {
		t.Fatalf("resources = %v, want only the connected upstream's", resources)
	}

	// A prompt nobody reachable serves may be the unconnected server's, so what
	// that server waits on is the answer, as Resolve gives it for a tool.
	_, err = c.GetPrompt(context.Background(), rc, namedFor(regPerUser, "summarize"), nil)
	var notConnected *ApplicationNotConnectedError
	if !errors.As(err, &notConnected) || notConnected.Provider != "com.notion/mcp" {
		t.Fatalf("error = %v, want ApplicationNotConnectedError for notion", err)
	}
}

func TestComposer_PromptsAndResourcesWhenNoUpstreamHasAnAccount(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "notion", "https://notion.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://notion.example.com/mcp": {prompts: prompts("summarize"), resources: []Resource{{URI: "notion://pages"}}},
	}}
	creds := &fakeCreds{err: &ApplicationNotConnectedError{Provider: "com.notion/mcp", Registry: "notion"}}
	c := NewComposer(dialer, creds, newMapCache(), slog.New(slog.DiscardHandler))
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)

	_, promptsErr := c.ListPrompts(context.Background(), rc)
	_, resourcesErr := c.ListResources(context.Background(), rc)
	for kind, err := range map[string]error{"prompts": promptsErr, "resources": resourcesErr} {
		var notConnected *ApplicationNotConnectedError
		if !errors.As(err, &notConnected) {
			t.Fatalf("%s: error = %v, want ApplicationNotConnectedError", kind, err)
		}
		if errors.Is(err, ErrUpstreamUnavailable) {
			t.Fatalf("%s: error = %v reads as an unreachable upstream", kind, err)
		}
	}
}

// evictingCache is a mapCache that can drop entries by prefix, as the TTL map
// the gateway wires can.
type evictingCache struct{ *mapCache }

func (c evictingCache) DeleteByPrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.m {
		if strings.HasPrefix(key, prefix) {
			delete(c.m, key)
		}
	}
}

// A call that finds the account gone drops the server's cached lists, so the
// next listing says the server needs connecting instead of serving the tools
// every call to which is now refused.
func TestComposer_InvokeNeedingAnAccountForgetsTheCachedLists(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{"https://linear.example.com/mcp": {tools: tools("search")}}}
	creds := &fakeCreds{}
	c := NewComposer(dialer, creds, evictingCache{newMapCache()}, slog.New(slog.DiscardHandler))
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen}}
	rc := routable(consumer, reg)
	ctx := context.Background()

	if _, err := c.ListTools(ctx, rc); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	target, err := c.Resolve(ctx, rc, namedFor(reg, "search"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	creds.err = &ConsentRequiredError{Provider: "linear", Ticket: "tk", Path: "/store/mcp"}
	var consentErr *ConsentRequiredError
	if _, err := c.Invoke(ctx, rc, target, json.RawMessage(`{}`)); !errors.As(err, &consentErr) {
		t.Fatalf("Invoke error = %v, want ConsentRequiredError", err)
	}
	if _, err := c.ListTools(ctx, rc); !errors.As(err, &consentErr) {
		t.Fatalf("ListTools after a refused call = %v, want ConsentRequiredError, not the cached tools", err)
	}
}
