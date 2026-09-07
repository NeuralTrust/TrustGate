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
	"errors"
	"fmt"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"golang.org/x/sync/errgroup"
)

const discoveryFanOut = 8

const (
	negativeTTL      = 10 * time.Second
	discoveryTimeout = 15 * time.Second
)

type DiscoveryCache interface {
	Get(key string) (any, bool)
	Set(key string, value any)
}

type discoveryFailure struct {
	err   error
	until time.Time
}

type discovered[T any] struct {
	registry *registrydomain.Registry
	items    []T
	err      error
}

func discoverAll[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	registries []*registrydomain.Registry,
	kind string,
	list func(context.Context, Upstream) ([]T, error),
) []discovered[T] {
	out := make([]discovered[T], len(registries))
	if len(registries) == 1 {
		items, err := discoverCached(c, ctx, rc, registries[0], kind, list)
		out[0] = discovered[T]{registry: registries[0], items: items, err: err}
		return out
	}
	var group errgroup.Group
	group.SetLimit(discoveryFanOut)
	for i, reg := range registries {
		out[i] = discovered[T]{registry: reg}
		group.Go(func() error {
			items, err := discoverCached(c, ctx, rc, reg, kind, list)
			out[i].items, out[i].err = items, err
			return nil
		})
	}
	// Every goroutine reports its own outcome, so the group never carries one.
	_ = group.Wait()
	return out
}

func federate[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	kind string,
	list func(context.Context, Upstream) ([]T, error),
	filter func(*registrydomain.Registry, []T) []T,
) ([]T, error) {
	items, degraded, err := federateWithStats(c, ctx, rc, kind, list, filter)
	if degraded {
		markCompositionDegraded(ctx)
	}
	return items, err
}

// federateWithStats composes one primitive kind across every bound registry and
// reports whether the composition was partial. A skipped registry means the
// returned surface is smaller than the consumer's real one, which a caller that
// diffs successive compositions must be able to tell apart from a genuine
// removal: without it a transient upstream blip shrinks the surface, announces a
// change, and announces another on recovery (RUN-1104 D6).
func federateWithStats[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	kind string,
	list func(context.Context, Upstream) ([]T, error),
	filter func(*registrydomain.Registry, []T) []T,
) ([]T, bool, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, false, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed

	var out []T
	reachable := 0
	degraded := false
	var firstConsent *ConsentRequiredError
	for _, found := range discoverAll(c, ctx, rc, registries, kind, list) {
		reg := found.registry
		if found.err != nil {
			if ctx.Err() != nil {
				return nil, false, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(found.err, &consentErr) {
				if firstConsent == nil {
					firstConsent = consentErr
				}
				degraded = true
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
				continue
			}
			if !failOpen {
				return nil, false, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, found.err)
			}
			degraded = true
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", found.err)
			continue
		}
		reachable++
		out = append(out, filter(reg, found.items)...)
	}
	if reachable == 0 {
		if firstConsent != nil {
			return nil, false, firstConsent
		}
		return nil, false, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	return out, degraded, nil
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

// HasNonLegacyMCPRegistry reports whether the consumer binds at least one MCP
// registry that is not pinned to the legacy protocol.
func HasNonLegacyMCPRegistry(rc *appconsumer.RoutableConsumer) bool {
	if rc == nil {
		return false
	}
	for _, reg := range mcpRegistries(rc) {
		if reg.MCPTarget.ProtocolMode != registrydomain.MCPProtocolModeLegacy {
			return true
		}
	}
	return false
}

func (c *composer) discoverTools(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	registries []*registrydomain.Registry,
) []discovered[Tool] {
	return discoverAll(c, ctx, rc, registries, "tools", func(ctx context.Context, up Upstream) ([]Tool, error) {
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
	if !cacheable {
		return askUpstream(c, ctx, rc, reg, list)
	}
	if items, err, ok := cachedDiscovery[T](c, key); ok {
		return items, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := c.flight.DoChan(key, func() (any, error) {
		if items, err, ok := cachedDiscovery[T](c, key); ok {
			return items, err
		}
		flightCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
		defer cancel()
		items, err := askUpstream(c, flightCtx, rc, reg, list)
		if err != nil {
			if !isContextError(err) {
				c.rememberFailure(key, err)
			}
			return nil, err
		}
		c.discovery.Set(key, items)
		return items, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case completed := <-result:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if completed.Err != nil {
			return nil, completed.Err
		}
		shared := completed.Val
		items, ok := shared.([]T)
		if !ok {
			return nil, fmt.Errorf("mcp discovery: unexpected cached type for %q", kind)
		}
		return items, nil
	}
}

func askUpstream[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	list func(context.Context, Upstream) ([]T, error),
) ([]T, error) {
	return invokeUpstream(c, ctx, rc, reg, upstreamReplaySafe, func(up Upstream) ([]T, error) {
		return list(ctx, up)
	})
}

func cachedDiscovery[T any](c *composer, key string) ([]T, error, bool) {
	cached, ok := c.discovery.Get(key)
	if !ok {
		return nil, nil, false
	}
	if items, ok := cached.([]T); ok {
		return items, nil, true
	}
	if failure, ok := cached.(discoveryFailure); ok && time.Now().Before(failure.until) {
		return nil, failure.err, true
	}
	return nil, nil, false
}

// rememberFailure holds on to an unreachable upstream for a few seconds so it
// is dialled once per window rather than once per request. Consent is left out:
// it is the user's to resolve, and resolving it should take effect at once. So
// is a caller that ran out of its own budget: the cache is shared by every
// request for the registry, and a bounded re-authorization pass giving up is the
// shortest budget any of them has (RUN-1104 D7).
func (c *composer) rememberFailure(key string, err error) {
	if isContextError(err) {
		return
	}
	var consentErr *ConsentRequiredError
	if errors.As(err, &consentErr) {
		return
	}
	c.discovery.Set(key, discoveryFailure{err: err, until: time.Now().Add(negativeTTL)})
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func discoveryKey(ctx context.Context, reg *registrydomain.Registry, kind string) (string, bool) {
	key := kind + ":" + reg.ID.String() + ":" + reg.UpdatedAt.UTC().Format("20060102150405.000")
	perPrincipal := perPrincipalAuth(reg) ||
		(reg.MCPTarget != nil && reg.MCPTarget.HasURLVariables())
	if !perPrincipal {
		return key, true
	}
	fingerprint := principalFingerprint(ctx)
	if fingerprint == "" {
		return "", false
	}
	// The cache key keeps the 64-bit prefix it has always used; the task handle
	// binds the full digest.
	return key + ":" + fingerprint[:discoveryFingerprintHexLen], true
}

// discoveryFingerprintHexLen is the hex width of the truncated principal digest
// discovery cache keys are built from.
const discoveryFingerprintHexLen = 16
