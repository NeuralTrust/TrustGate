package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
)

type fakeUpstream struct {
	tools    []mcpclient.Tool
	listErr  error
	lastCall string
	result   json.RawMessage
}

func (f *fakeUpstream) ListTools(context.Context) ([]mcpclient.Tool, error) {
	return f.tools, f.listErr
}

func (f *fakeUpstream) CallTool(_ context.Context, name string, _ json.RawMessage) (json.RawMessage, error) {
	f.lastCall = name
	return f.result, nil
}

func (f *fakeUpstream) Close(context.Context) {}

type fakeDialer struct {
	upstreams map[string]*fakeUpstream // by URL
	dialErr   map[string]error
}

func (f *fakeDialer) Connect(_ context.Context, target mcpclient.Target) (Upstream, error) {
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

func newTestComposer(dialer Dialer) Composer {
	mgr := cache.NewTTLMapManager(time.Minute)
	return NewComposer(dialer, mgr, slog.New(slog.DiscardHandler))
}

func tools(names ...string) []mcpclient.Tool {
	out := make([]mcpclient.Tool, 0, len(names))
	for _, n := range names {
		out = append(out, mcpclient.Tool{Name: n})
	}
	return out
}

func toolNames(ts []mcpclient.Tool) []string {
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

func TestComposer_ListTools_ToolkitSelectAndRename(t *testing.T) {
	t.Parallel()
	regA := mcpRegistry(t, "github", "https://a.example.com/mcp")
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("create_issue", "list_repos", "delete_repo")},
	}}
	c := newTestComposer(dialer)

	consumer := &consumerdomain.Consumer{
		Type: consumerdomain.TypeMCP,
		Toolkit: consumerdomain.Toolkit{
			{RegistryID: regA.ID, Tool: "create_issue", ExposeAs: "gh_create_issue"},
			{RegistryID: regA.ID, Tool: "list_repos"},
		},
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
			"https://b.example.com/mcp": mcpclient.ErrUnreachable,
		},
	}
	c := newTestComposer(dialer)

	t.Run("closed rejects", func(t *testing.T) {
		t.Parallel()
		consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, FailMode: consumerdomain.FailModeClosed}
		_, err := c.ListTools(context.Background(), routable(consumer, regA, regB))
		if !errors.Is(err, ErrUpstreamUnavailable) {
			t.Fatalf("error = %v, want ErrUpstreamUnavailable", err)
		}
	})

	t.Run("open serves reachable", func(t *testing.T) {
		t.Parallel()
		consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, FailMode: consumerdomain.FailModeOpen}
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
