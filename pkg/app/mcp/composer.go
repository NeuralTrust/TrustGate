// Package mcp composes virtual MCP servers: it federates the tools,
// resources, and prompts of the MCP registries attached to a consumer,
// applies the consumer's toolkit (select / rename / wildcard, tools only),
// resolves name collisions, and routes calls back to the owning upstream
// server.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
)

// Upstream is one initialized connection to an upstream MCP server.
type Upstream interface {
	ListTools(ctx context.Context) ([]mcpclient.Tool, error)
	CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error)
	ListResources(ctx context.Context) ([]mcpclient.Resource, error)
	ListResourceTemplates(ctx context.Context) ([]mcpclient.ResourceTemplate, error)
	ReadResource(ctx context.Context, uri string) (json.RawMessage, error)
	ListPrompts(ctx context.Context) ([]mcpclient.Prompt, error)
	GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error)
	SupportsResources() bool
	SupportsPrompts() bool
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
	// ListResources merges the resources of every upstream (URI-addressed; no renaming).
	ListResources(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.Resource, error)
	// ListResourceTemplates merges the resource templates of every upstream.
	ListResourceTemplates(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.ResourceTemplate, error)
	// ReadResource routes a resource URI to the upstream that serves it.
	ReadResource(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, error)
	// ListPrompts returns the composed prompt surface (collisions auto-prefixed).
	ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.Prompt, error)
	// GetPrompt routes an exposed prompt name to its upstream server and renders it.
	GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error)
}

var _ Composer = (*composer)(nil)

type composer struct {
	dialer     Dialer
	creds      CredentialResolver
	toolsCache *cache.TTLMap
	logger     *slog.Logger
}

func NewComposer(dialer Dialer, creds CredentialResolver, manager *cache.TTLMapManager, logger *slog.Logger) Composer {
	return &composer{
		dialer:     dialer,
		creds:      creds,
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
		target, err := c.target(ctx, rc, b.registry)
		if err != nil {
			return nil, err
		}
		up, err := c.dialer.Connect(ctx, target)
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

// ListResources merges the resources of every reachable upstream, filtered by
// the consumer toolkit. Resources are URI-addressed, so no renaming applies.
func (c *composer) ListResources(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.Resource, error) {
	toolkit := rc.Consumer.Toolkit
	return federate(c, ctx, rc, "resources",
		func(ctx context.Context, up Upstream) ([]mcpclient.Resource, error) {
			return up.ListResources(ctx)
		},
		func(reg *registrydomain.Registry, resources []mcpclient.Resource) []mcpclient.Resource {
			if len(toolkit) == 0 {
				return resources
			}
			out := make([]mcpclient.Resource, 0, len(resources))
			for _, r := range resources {
				if toolkit.AllowsResource(reg.ID, r.URI) {
					out = append(out, r)
				}
			}
			return out
		})
}

// ListResourceTemplates merges the resource templates of every reachable
// upstream. With a non-empty toolkit, a registry's templates are exposed only
// when the registry has at least one resource entry; the URIs expanded from a
// template are still enforced individually at read time.
func (c *composer) ListResourceTemplates(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.ResourceTemplate, error) {
	toolkit := rc.Consumer.Toolkit
	return federate(c, ctx, rc, "resource-templates",
		func(ctx context.Context, up Upstream) ([]mcpclient.ResourceTemplate, error) {
			return up.ListResourceTemplates(ctx)
		},
		func(reg *registrydomain.Registry, templates []mcpclient.ResourceTemplate) []mcpclient.ResourceTemplate {
			if len(toolkit) == 0 || len(toolkit.ResourceEntriesFor(reg.ID)) > 0 {
				return templates
			}
			return nil
		})
}

// ReadResource routes a URI to the upstream that serves it: the upstream
// listing the exact URI wins; template-addressed URIs fall back to trying
// each resource-capable upstream in attachment order.
func (c *composer) ReadResource(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	toolkit := rc.Consumer.Toolkit
	for _, reg := range registries {
		if !toolkit.AllowsResource(reg.ID, uri) {
			continue
		}
		resources, err := discoverCached(c, ctx, rc, reg, "resources", func(ctx context.Context, up Upstream) ([]mcpclient.Resource, error) {
			return up.ListResources(ctx)
		})
		if err != nil {
			continue // unreachable upstreams are handled by the fallback pass
		}
		for _, r := range resources {
			if r.URI == uri {
				return c.readFrom(ctx, rc, reg, uri)
			}
		}
	}
	var lastErr error
	for _, reg := range registries {
		if !toolkit.AllowsResource(reg.ID, uri) {
			continue
		}
		raw, err := c.readFrom(ctx, rc, reg, uri)
		if err == nil {
			return raw, nil
		}
		if errors.Is(err, mcpclient.ErrNotSupported) {
			continue
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("%w: %s", ErrResourceNotFound, uri)
}

func (c *composer) readFrom(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, uri string) (json.RawMessage, error) {
	target, err := c.target(ctx, rc, reg)
	if err != nil {
		return nil, err
	}
	up, err := c.dialer.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer up.Close(ctx)
	return up.ReadResource(ctx, uri)
}

// ListPrompts returns the composed prompt surface; name collisions across
// upstreams are auto-prefixed with the registry name like tools.
func (c *composer) ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]mcpclient.Prompt, error) {
	bindings, err := c.composePrompts(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]mcpclient.Prompt, 0, len(bindings))
	for _, b := range bindings {
		p := b.prompt
		p.Name = b.exposed
		out = append(out, p)
	}
	return out, nil
}

// GetPrompt routes an exposed prompt name to its upstream server and renders it.
func (c *composer) GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error) {
	bindings, err := c.composePrompts(ctx, rc)
	if err != nil {
		return nil, err
	}
	for _, b := range bindings {
		if b.exposed != name {
			continue
		}
		target, err := c.target(ctx, rc, b.registry)
		if err != nil {
			return nil, err
		}
		up, err := c.dialer.Connect(ctx, target)
		if err != nil {
			return nil, err
		}
		defer up.Close(ctx)
		return up.GetPrompt(ctx, b.prompt.Name, arguments)
	}
	return nil, fmt.Errorf("%w: %s", ErrPromptNotFound, name)
}

// promptBinding maps an exposed prompt name to its upstream registry and prompt.
type promptBinding struct {
	registry *registrydomain.Registry
	prompt   mcpclient.Prompt
	exposed  string
}

func (c *composer) composePrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]promptBinding, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode == consumerdomain.FailModeOpen
	toolkit := rc.Consumer.Toolkit

	var candidates []promptBinding
	reachable := 0
	for _, reg := range registries {
		prompts, err := discoverCached(c, ctx, rc, reg, "prompts", func(ctx context.Context, up Upstream) ([]mcpclient.Prompt, error) {
			return up.ListPrompts(ctx)
		})
		if err != nil {
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, err)
			}
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", err)
			continue
		}
		reachable++
		candidates = append(candidates, selectPrompts(toolkit, reg, prompts)...)
	}
	if reachable == 0 {
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	items := make([]exposedName, len(candidates))
	for i, b := range candidates {
		items[i] = exposedName{name: b.exposed, registry: b.registry.Name}
	}
	for i, name := range resolveExposedNames(items) {
		candidates[i].exposed = name
	}
	return candidates, nil
}

// selectPrompts applies the consumer toolkit to one registry's prompt list,
// mirroring selectTools: an empty toolkit exposes everything; otherwise only
// listed prompt entries (wildcard or exact) are exposed, with optional renames.
func selectPrompts(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry, prompts []mcpclient.Prompt) []promptBinding {
	if len(toolkit) == 0 {
		out := make([]promptBinding, 0, len(prompts))
		for _, p := range prompts {
			out = append(out, promptBinding{registry: reg, prompt: p, exposed: p.Name})
		}
		return out
	}
	entries := toolkit.PromptEntriesFor(reg.ID)
	if len(entries) == 0 {
		return nil
	}
	byName := make(map[string]mcpclient.Prompt, len(prompts))
	for _, p := range prompts {
		byName[p.Name] = p
	}
	var out []promptBinding
	seen := make(map[string]struct{}, len(prompts))
	for _, e := range entries {
		if e.Prompt == consumerdomain.ToolWildcard {
			for _, p := range prompts {
				if _, dup := seen[p.Name]; dup {
					continue
				}
				seen[p.Name] = struct{}{}
				out = append(out, promptBinding{registry: reg, prompt: p, exposed: p.Name})
			}
			continue
		}
		p, ok := byName[e.Prompt]
		if !ok {
			continue // prompt disappeared upstream; expose the rest
		}
		if _, dup := seen[p.Name]; dup {
			continue
		}
		seen[p.Name] = struct{}{}
		exposed := p.Name
		if e.ExposeAs != "" {
			exposed = e.ExposeAs
		}
		out = append(out, promptBinding{registry: reg, prompt: p, exposed: exposed})
	}
	return out
}

// federate merges one list-shaped surface across every upstream, honoring the
// consumer's fail_mode. filter applies the per-registry toolkit allowlist.
func federate[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	kind string,
	list func(context.Context, Upstream) ([]T, error),
	filter func(*registrydomain.Registry, []T) []T,
) ([]T, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode == consumerdomain.FailModeOpen

	var out []T
	reachable := 0
	for _, reg := range registries {
		items, err := discoverCached(c, ctx, rc, reg, kind, list)
		if err != nil {
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, err)
			}
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", err)
			continue
		}
		reachable++
		out = append(out, filter(reg, items)...)
	}
	if reachable == 0 {
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	return out, nil
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
	return discoverCached(c, ctx, rc, reg, "tools", func(ctx context.Context, up Upstream) ([]mcpclient.Tool, error) {
		return up.ListTools(ctx)
	})
}

// discoverCached lists one surface of one upstream, with a short-lived cache
// keyed by kind + registry id + updated_at so config changes invalidate
// immediately.
func discoverCached[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	kind string,
	list func(context.Context, Upstream) ([]T, error),
) ([]T, error) {
	key := kind + ":" + reg.ID.String() + ":" + reg.UpdatedAt.UTC().Format("20060102150405.000")
	if cached, ok := c.toolsCache.Get(key); ok {
		if items, ok := cached.([]T); ok {
			return items, nil
		}
	}
	target, err := c.target(ctx, rc, reg)
	if err != nil {
		return nil, err
	}
	up, err := c.dialer.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer up.Close(ctx)
	items, err := list(ctx, up)
	if err != nil {
		return nil, err
	}
	c.toolsCache.Set(key, items)
	return items, nil
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
	items := make([]exposedName, len(candidates))
	for i, b := range candidates {
		items[i] = exposedName{name: b.exposed, registry: b.registry.Name}
	}
	out := make([]binding, 0, len(candidates))
	for i, name := range resolveExposedNames(items) {
		b := candidates[i]
		b.exposed = name
		out = append(out, b)
	}
	return out
}

// exposedName is one candidate name plus its owning registry, for collision
// resolution shared by tools and prompts.
type exposedName struct {
	name     string
	registry string
}

// resolveExposedNames auto-prefixes colliding names with the sanitized
// registry name ({server}_{name}); remaining duplicates get numeric suffixes.
func resolveExposedNames(items []exposedName) []string {
	counts := make(map[string]int, len(items))
	for _, it := range items {
		counts[it.name]++
	}
	taken := make(map[string]struct{}, len(items))
	out := make([]string, len(items))
	for i, it := range items {
		name := it.name
		if counts[name] > 1 {
			name = sanitizeName(it.registry) + "_" + it.name
		}
		base := name
		for n := 2; ; n++ {
			if _, dup := taken[name]; !dup {
				break
			}
			name = fmt.Sprintf("%s_%d", base, n)
		}
		taken[name] = struct{}{}
		out[i] = name
	}
	return out
}

var invalidNameChars = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeName(s string) string {
	s = invalidNameChars.ReplaceAllString(strings.TrimSpace(s), "_")
	return strings.Trim(s, "_")
}

// target builds the upstream connection target: static config (none/static
// modes, headers, session pin key) plus the per-principal credential for the
// passthrough/exchange/forwarded modes via the resolver.
func (c *composer) target(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) (mcpclient.Target, error) {
	t := targetFor(ctx, rc, reg)
	if c.creds != nil {
		if err := c.creds.Apply(ctx, rc, reg, &t); err != nil {
			return mcpclient.Target{}, err
		}
	}
	return t, nil
}

// targetFor builds the upstream connection target, applying the registry's
// downstream auth config (none/static) and the session pin key. Per-user
// downstream modes get a per-principal pin so sessions never cross users.
func targetFor(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) mcpclient.Target {
	t := Target(reg)
	if rc != nil && rc.Consumer != nil {
		t.PinKey = fmt.Sprintf("%s:%s:%s", rc.Consumer.GatewayID, rc.Consumer.ID, reg.ID)
		if perPrincipalAuth(reg) {
			if p := identity.PrincipalFromContext(ctx); p != nil {
				t.PinKey += ":" + p.Subject
			}
		}
	}
	return t
}

func perPrincipalAuth(reg *registrydomain.Registry) bool {
	if reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
		return false
	}
	switch reg.MCPTarget.Auth.Mode {
	case registrydomain.MCPAuthModePassthrough, registrydomain.MCPAuthModeExchange, registrydomain.MCPAuthModeForwarded:
		return true
	}
	return false
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
