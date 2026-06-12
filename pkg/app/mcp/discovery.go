package mcp

import (
	"context"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

// DiscoveryCache holds short-lived discovery results (tools, prompts,
// resources of one upstream). Implemented in infra (TTL map); entries are
// keyed so a registry config change invalidates immediately.
type DiscoveryCache interface {
	Get(key string) (any, bool)
	Set(key string, value any)
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
func (c *composer) discover(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) ([]Tool, error) {
	return discoverCached(c, ctx, rc, reg, "tools", func(ctx context.Context, up Upstream) ([]Tool, error) {
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
	if cached, ok := c.discovery.Get(key); ok {
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
	c.discovery.Set(key, items)
	return items, nil
}
