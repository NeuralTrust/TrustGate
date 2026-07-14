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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type DiscoveryCache interface {
	Get(key string) (any, bool)
	Set(key string, value any)
}

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
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed

	var out []T
	reachable := 0
	for _, reg := range registries {
		items, err := discoverCached(c, ctx, rc, reg, kind, list)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(err, &consentErr) {
				return nil, err
			}
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

func (c *composer) discover(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) ([]Tool, error) {
	return discoverCached(c, ctx, rc, reg, "tools", func(ctx context.Context, up Upstream) ([]Tool, error) {
		return up.ListTools(ctx)
	})
}

func discoverCached[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	kind string,
	list func(context.Context, Upstream) ([]T, error),
) ([]T, error) {
	key, cacheable := discoveryKey(ctx, reg, kind)
	if cacheable {
		if cached, ok := c.discovery.Get(key); ok {
			if items, ok := cached.([]T); ok {
				return items, nil
			}
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
	if cacheable {
		c.discovery.Set(key, items)
	}
	return items, nil
}

func discoveryKey(ctx context.Context, reg *registrydomain.Registry, kind string) (string, bool) {
	key := kind + ":" + reg.ID.String() + ":" + reg.UpdatedAt.UTC().Format("20060102150405.000")
	if !perPrincipalAuth(reg) {
		return key, true
	}
	p := identity.PrincipalFromContext(ctx)
	if p == nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(p.Issuer + "|" + p.Subject))
	return key + ":" + hex.EncodeToString(sum[:8]), true
}
