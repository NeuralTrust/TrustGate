// Package mcp composes virtual MCP servers: it federates the tools of the
// MCP registries attached to a consumer, applies the consumer's toolkit
// (select / rename / wildcard), resolves name collisions, and routes tool
// calls back to the owning upstream server.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
)

// Upstream is one initialized connection to an upstream MCP server.
type Upstream interface {
	ListTools(ctx context.Context) ([]mcpclient.Tool, error)
	CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error)
	Close(ctx context.Context)
}

// Dialer opens connections to upstream MCP servers.
type Dialer interface {
	Connect(ctx context.Context, target mcpclient.Target) (Upstream, error)
}

// DialerFunc adapts a function to the Dialer interface.
type DialerFunc func(ctx context.Context, target mcpclient.Target) (Upstream, error)

func (f DialerFunc) Connect(ctx context.Context, target mcpclient.Target) (Upstream, error) {
	return f(ctx, target)
}

//go:generate mockery --name=Composer --dir=. --output=./mocks --filename=mcp_composer_mock.go --case=underscore --with-expecter
type Composer interface {
	// ListTools returns the composed tool surface of the consumer's virtual MCP.
	ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.Tool, error)
	// CallTool routes an exposed tool name to its upstream server and invokes it.
	CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error)
}

var _ Composer = (*composer)(nil)

type composer struct {
	dialer     Dialer
	toolsCache *cache.TTLMap
	logger     *slog.Logger
}

func NewComposer(dialer Dialer, manager *cache.TTLMapManager, logger *slog.Logger) Composer {
	return &composer{
		dialer:     dialer,
		toolsCache: manager.GetTTLMap(cache.MCPToolsTTLName),
		logger:     logger,
	}
}

// binding maps an exposed tool name to its upstream registry and tool.
type binding struct {
	registry *registrydomain.Registry
	tool     mcpclient.Tool
	exposed  string
}

func (c *composer) ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.Tool, error) {
	bindings, err := c.compose(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]mcpclient.Tool, 0, len(bindings))
	for _, b := range bindings {
		t := b.tool
		t.Name = b.exposed
		out = append(out, t)
	}
	return out, nil
}

func (c *composer) CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error) {
	bindings, err := c.compose(ctx, rc)
	if err != nil {
		return nil, err
	}
	for _, b := range bindings {
		if b.exposed != name {
			continue
		}
		up, err := c.dialer.Connect(ctx, targetFor(rc, b.registry))
		if err != nil {
			return nil, err
		}
		defer up.Close(ctx)
		return up.CallTool(ctx, b.tool.Name, arguments)
	}
	return nil, fmt.Errorf("%w: %s", ErrToolNotFound, name)
}

// compose discovers upstream tools, applies the toolkit, and resolves names.
func (c *composer) compose(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]binding, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode == consumerdomain.FailModeOpen
	toolkit := rc.Consumer.Toolkit

	var candidates []binding
	reachable := 0
	for _, reg := range registries {
		tools, err := c.discover(ctx, rc, reg)
		if err != nil {
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, err)
			}
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", err)
			continue
		}
		reachable++
		candidates = append(candidates, selectTools(toolkit, reg, tools)...)
	}
	if reachable == 0 {
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	return resolveNames(candidates), nil
}

func mcpRegistries(rc *appconsumer.RoutableConsumer) []*registrydomain.Registry {
	var out []*registrydomain.Registry
	for _, reg := range rc.Registries {
		if reg.IsMCP() && reg.MCPTarget != nil {
			out = append(out, reg)
		}
	}
	return out
}

// discover lists the tools of one upstream, with a short-lived cache keyed by
// registry id + updated_at so config changes invalidate immediately.
func (c *composer) discover(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) ([]mcpclient.Tool, error) {
	key := reg.ID.String() + ":" + reg.UpdatedAt.UTC().Format("20060102150405.000")
	if cached, ok := c.toolsCache.Get(key); ok {
		if tools, ok := cached.([]mcpclient.Tool); ok {
			return tools, nil
		}
	}
	up, err := c.dialer.Connect(ctx, targetFor(rc, reg))
	if err != nil {
		return nil, err
	}
	defer up.Close(ctx)
	tools, err := up.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	c.toolsCache.Set(key, tools)
	return tools, nil
}

// selectTools applies the consumer toolkit to one registry's tool list. An
// empty toolkit exposes everything; otherwise only listed entries (wildcard
// or exact) are exposed, with optional renames.
func selectTools(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry, tools []mcpclient.Tool) []binding {
	if len(toolkit) == 0 {
		out := make([]binding, 0, len(tools))
		for _, t := range tools {
			out = append(out, binding{registry: reg, tool: t, exposed: t.Name})
		}
		return out
	}
	entries := toolkit.EntriesFor(reg.ID)
	if len(entries) == 0 {
		return nil
	}
	byName := make(map[string]mcpclient.Tool, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
	}
	var out []binding
	seen := make(map[string]struct{}, len(tools))
	for _, e := range entries {
		if e.Tool == consumerdomain.ToolWildcard {
			for _, t := range tools {
				if _, dup := seen[t.Name]; dup {
					continue
				}
				seen[t.Name] = struct{}{}
				out = append(out, binding{registry: reg, tool: t, exposed: t.Name})
			}
			continue
		}
		t, ok := byName[e.Tool]
		if !ok {
			continue // tool disappeared upstream; expose the rest
		}
		if _, dup := seen[t.Name]; dup {
			continue
		}
		seen[t.Name] = struct{}{}
		exposed := t.Name
		if e.ExposeAs != "" {
			exposed = e.ExposeAs
		}
		out = append(out, binding{registry: reg, tool: t, exposed: exposed})
	}
	return out
}

// resolveNames auto-prefixes colliding tool names with the sanitized registry
// name ({server}_{tool}); explicit expose_as aliases always win.
func resolveNames(candidates []binding) []binding {
	counts := make(map[string]int, len(candidates))
	for _, b := range candidates {
		counts[b.exposed]++
	}
	taken := make(map[string]struct{}, len(candidates))
	out := make([]binding, 0, len(candidates))
	for _, b := range candidates {
		name := b.exposed
		if counts[name] > 1 {
			name = sanitizeName(b.registry.Name) + "_" + b.exposed
		}
		base := name
		for i := 2; ; i++ {
			if _, dup := taken[name]; !dup {
				break
			}
			name = fmt.Sprintf("%s_%d", base, i)
		}
		taken[name] = struct{}{}
		b.exposed = name
		out = append(out, b)
	}
	return out
}

var invalidNameChars = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeName(s string) string {
	s = invalidNameChars.ReplaceAllString(strings.TrimSpace(s), "_")
	return strings.Trim(s, "_")
}

// targetFor builds the upstream connection target, applying the registry's
// downstream auth config (none/static) and the session pin key.
func targetFor(rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) mcpclient.Target {
	t := Target(reg)
	if rc != nil && rc.Consumer != nil {
		t.PinKey = fmt.Sprintf("%s:%s:%s", rc.Consumer.GatewayID, rc.Consumer.ID, reg.ID)
	}
	return t
}

// Target builds the raw connection target for an MCP registry (no session
// pinning). Used by the composer and by admin tool introspection.
func Target(reg *registrydomain.Registry) mcpclient.Target {
	t := reg.MCPTarget
	headers := make(map[string]string, len(t.Headers)+1)
	for k, v := range t.Headers {
		headers[k] = v
	}
	if t.Auth != nil && t.Auth.Mode == registrydomain.MCPAuthModeStatic {
		headers[t.Auth.Header] = t.Auth.Value
	}
	return mcpclient.Target{URL: t.URL, Headers: headers}
}
