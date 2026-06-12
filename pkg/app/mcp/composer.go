// Package mcp composes virtual MCP servers: it federates the tools,
// resources, and prompts of the MCP registries attached to a consumer,
// applies the consumer's toolkit (select / rename / wildcard, tools only),
// resolves name collisions, and routes calls back to the owning upstream
// server.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

//go:generate mockery --name=Composer --dir=. --output=./mocks --filename=mcp_composer_mock.go --case=underscore --with-expecter
type Composer interface {
	// ListTools returns the composed tool surface of the consumer's virtual MCP.
	ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error)
	// CallTool routes an exposed tool name to its upstream server and invokes it.
	CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error)
	// ListResources merges the resources of every upstream (URI-addressed; no renaming).
	ListResources(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Resource, error)
	// ListResourceTemplates merges the resource templates of every upstream.
	ListResourceTemplates(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]ResourceTemplate, error)
	// ReadResource routes a resource URI to the upstream that serves it.
	ReadResource(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, error)
	// ListPrompts returns the composed prompt surface (collisions auto-prefixed).
	ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Prompt, error)
	// GetPrompt routes an exposed prompt name to its upstream server and renders it.
	GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error)
}

var _ Composer = (*composer)(nil)

type composer struct {
	dialer    Dialer
	creds     CredentialResolver
	discovery DiscoveryCache
	logger    *slog.Logger
}

func NewComposer(dialer Dialer, creds CredentialResolver, discovery DiscoveryCache, logger *slog.Logger) Composer {
	return &composer{
		dialer:    dialer,
		creds:     creds,
		discovery: discovery,
		logger:    logger,
	}
}

// binding maps an exposed tool name to its upstream registry and tool.
type binding struct {
	registry *registrydomain.Registry
	tool     Tool
	exposed  string
}

func (c *composer) ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error) {
	bindings, err := c.compose(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]Tool, 0, len(bindings))
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

// selectTools applies the consumer toolkit to one registry's tool list. An
// empty toolkit exposes everything; otherwise only listed entries (wildcard
// or exact) are exposed, with optional renames.
func selectTools(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry, tools []Tool) []binding {
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
	byName := make(map[string]Tool, len(tools))
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
