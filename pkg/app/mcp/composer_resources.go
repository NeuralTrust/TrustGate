package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func (c *composer) ListResources(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Resource, error) {
	toolkit := rc.Consumer.Toolkit()
	return federate(c, ctx, rc, "resources",
		func(ctx context.Context, up Upstream) ([]Resource, error) {
			return up.ListResources(ctx)
		},
		func(reg *registrydomain.Registry, resources []Resource) []Resource {
			if toolkit == nil {
				return resources
			}
			out := make([]Resource, 0, len(resources))
			for _, r := range resources {
				if toolkit.AllowsResource(reg.ID, r.URI) {
					out = append(out, r)
				}
			}
			return out
		})
}

func (c *composer) ListResourceTemplates(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]ResourceTemplate, error) {
	toolkit := rc.Consumer.Toolkit()
	return federate(c, ctx, rc, "resource-templates",
		func(ctx context.Context, up Upstream) ([]ResourceTemplate, error) {
			return up.ListResourceTemplates(ctx)
		},
		func(reg *registrydomain.Registry, templates []ResourceTemplate) []ResourceTemplate {
			if toolkit == nil || len(toolkit.ResourceEntriesFor(reg.ID)) > 0 {
				return templates
			}
			return nil
		})
}

func (c *composer) ReadResource(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	toolkit := rc.Consumer.Toolkit()
	for _, reg := range registries {
		if !toolkit.AllowsResource(reg.ID, uri) {
			continue
		}
		resources, err := discoverCached(c, ctx, rc, reg, "resources", func(ctx context.Context, up Upstream) ([]Resource, error) {
			return up.ListResources(ctx)
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		for _, r := range resources {
			if r.URI == uri {
				return c.readFrom(ctx, rc, reg, uri)
			}
		}
	}
	var firstErr error
	for _, reg := range registries {
		if !toolkit.AllowsResource(reg.ID, uri) {
			continue
		}
		raw, err := c.readFrom(ctx, rc, reg, uri)
		if err == nil {
			return raw, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, ErrNotSupported) {
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
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
