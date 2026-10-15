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
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"golang.org/x/sync/errgroup"
)

const discoveryFanOut = 8

const (
	negativeTTL      = 10 * time.Second
	discoveryTimeout = 15 * time.Second
)

// discoveryFreshFor is how long a discovery is served as is. Past it the result
// is still served, but a refresh starts behind it (RUN-1633): every tools/call
// composes all of the consumer's upstreams to resolve the exposed name, and
// waiting on that refresh put a cold session or token refresh of the slowest
// upstream in front of every call made after a few minutes idle.
const discoveryFreshFor = 5 * time.Minute

// discoveryMaxAge bounds how stale a served discovery can be, so an upstream
// that stopped answering is eventually reported instead of hidden behind its
// last tool list.
const discoveryMaxAge = time.Hour

type DiscoveryCache interface {
	Get(key string) (any, bool)
	Set(key string, value any)
	Delete(key string)
}

// discoverySnapshot is a successful discovery. It stays servable until
// fetchedAt+discoveryMaxAge; past staleAfter, serving it also triggers a
// refresh.
type discoverySnapshot[T any] struct {
	items      []T
	fetchedAt  time.Time
	staleAfter time.Time
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
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed

	var out []T
	reachable := 0
	var firstConsent *ConsentRequiredError
	var firstNotConnected *ApplicationNotConnectedError
	for _, found := range discoverAll(c, ctx, rc, registries, kind, list) {
		reg := found.registry
		if found.err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(found.err, &consentErr) {
				if firstConsent == nil {
					firstConsent = consentErr
				}
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
				continue
			}
			// Skipped like a pending consent, as compose does for tools: an
			// account is what is missing, so it is not an unreachable upstream,
			// and a consumer that fails closed must not refuse the rest over it.
			var notConnected *ApplicationNotConnectedError
			if errors.As(found.err, &notConnected) {
				if firstNotConnected == nil {
					firstNotConnected = notConnected
				}
				c.logger.Info("mcp composer: skipping upstream with no account for this caller",
					"registry", reg.Name, "provider", notConnected.Provider, "shared", notConnected.Shared)
				continue
			}
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, found.err)
			}
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", found.err)
			continue
		}
		reachable++
		out = append(out, filter(reg, found.items)...)
	}
	if reachable == 0 {
		if firstConsent != nil {
			return nil, firstConsent
		}
		if firstNotConnected != nil {
			return nil, firstNotConnected
		}
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
	ask := func(ctx context.Context) ([]T, error) { return askUpstream(c, ctx, rc, reg, list) }
	if reg.MCPTarget != nil && reg.MCPTarget.HasURLVariables() {
		target := targetFor(ctx, rc, reg)
		if err := c.resolveURLVariables(ctx, rc, reg, &target); err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(target.URL))
		key += ":url:" + hex.EncodeToString(sum[:])
		ask = func(ctx context.Context) ([]T, error) {
			if c.creds != nil {
				if err := c.creds.Apply(ctx, rc, reg, &target); err != nil {
					return nil, err
				}
			}
			return invokeResolvedUpstream(c, ctx, rc, reg, target, func(up Upstream) ([]T, error) { return list(ctx, up) })
		}
	}

	if !cacheable {
		askCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
		defer cancel()
		return ask(askCtx)
	}
	now := time.Now()
	if items, hit, stale, err := cachedDiscovery[T](c, key, now); hit {
		if stale {
			revalidate(c, detachedFromRequest(ctx), key, ask)
		}
		return items, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// One discovery per key at a time. Without this, a burst arriving after the
	// entry expires all dials the same upstream, which is exactly when it is
	// least able to take it. The flight runs detached from the caller that
	// started it, so one client going away does not fail the others waiting on
	// the same key.
	result := c.flight.DoChan(key, func() (any, error) {
		if items, hit, stale, err := cachedDiscovery[T](c, key, time.Now()); hit && !stale {
			return items, err
		}
		return refreshDiscovery(c, context.WithoutCancel(ctx), key, ask)
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
		items, ok := completed.Val.([]T)
		if !ok {
			return nil, fmt.Errorf("mcp discovery: unexpected cached type for %q", kind)
		}
		return items, nil
	}
}

// revalidate refreshes a stale discovery in the background while the caller is
// served the snapshot it already has. The flight key deduplicates it against
// any other refresh of the same key.
func revalidate[T any](c *composer, ctx context.Context, key string, ask func(context.Context) ([]T, error)) {
	c.flight.DoChan(key, func() (any, error) {
		if items, hit, stale, err := cachedDiscovery[T](c, key, time.Now()); hit && !stale {
			return items, err
		}
		return refreshDiscovery(c, ctx, key, ask)
	})
}

func refreshDiscovery[T any](c *composer, ctx context.Context, key string, ask func(context.Context) ([]T, error)) ([]T, error) {
	askCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	items, err := ask(askCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && askCtx.Err() != nil {
			rememberFailure[T](c, key, fmt.Errorf("%w: discovery timed out", ErrUnreachable))
		} else {
			rememberFailure[T](c, key, err)
		}
		return nil, err
	}
	now := time.Now()
	c.discovery.Set(key, discoverySnapshot[T]{items: items, fetchedAt: now, staleAfter: now.Add(discoveryFreshFor)})
	return items, nil
}

// detachedFromRequest keeps the caller's identity and credentials for a
// background refresh but drops its cancellation and its trace, which belongs to
// a request that may have finished by the time the refresh writes to it.
func detachedFromRequest(ctx context.Context) context.Context {
	ctx = context.WithoutCancel(ctx)
	ctx = trace.NewContext(ctx, nil)
	return trace.NewSpanContext(ctx, nil)
}

func askUpstream[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	list func(context.Context, Upstream) ([]T, error),
) ([]T, error) {
	return invokeUpstream(c, ctx, rc, reg, func(up Upstream) ([]T, error) {
		return list(ctx, up)
	})
}

// cachedDiscovery reports a hit, which is either the tools an upstream served
// or the failure it answered with while that failure is still recent. A hit on
// a snapshot past its freshness is reported stale so the caller can refresh it.
func cachedDiscovery[T any](c *composer, key string, now time.Time) (items []T, hit, stale bool, err error) {
	cached, ok := c.discovery.Get(key)
	if !ok {
		return nil, false, false, nil
	}
	switch v := cached.(type) {
	case discoverySnapshot[T]:
		if now.After(v.fetchedAt.Add(discoveryMaxAge)) {
			return nil, false, false, nil
		}
		return v.items, true, now.After(v.staleAfter), nil
	case discoveryFailure:
		if now.Before(v.until) {
			return nil, true, false, v.err
		}
	}
	return nil, false, false, nil
}

// rememberFailure holds on to an unreachable upstream for a few seconds so it
// is dialled once per window rather than once per request. A snapshot still
// within its max age is kept and retried after the same window, since its tools
// are a better answer than an error for an upstream that blipped. A refusal
// fixable by connecting an account drops the entry instead: connecting it
// should take effect at once.
func rememberFailure[T any](c *composer, key string, err error) {
	if isContextError(err) {
		return
	}
	if fixableByConnecting(err) {
		c.discovery.Delete(key)
		return
	}
	now := time.Now()
	until := now.Add(negativeTTL)
	if cached, ok := c.discovery.Get(key); ok {
		if snap, ok := cached.(discoverySnapshot[T]); ok && now.Before(snap.fetchedAt.Add(discoveryMaxAge)) {
			snap.staleAfter = until
			c.discovery.Set(key, snap)
			return
		}
	}
	c.discovery.Set(key, discoveryFailure{err: err, until: until})
}

// discoveryEvictor is the part of a DiscoveryCache that can drop entries; the
// TTL map the gateway wires has it.
type discoveryEvictor interface {
	DeleteByPrefix(prefix string)
}

// discoveryKinds are the lists discovery caches per server.
var discoveryKinds = []string{"tools", "prompts", "resources"}

// forgetDiscovery drops what discovery cached about reg for this caller. A
// call that finds the caller's account gone — revoked from the Portal or the
// connect page, or no longer usable — would otherwise leave their tool list
// showing the server as ready, every tool in it refused, until the entry
// expired minutes later.
func (c *composer) forgetDiscovery(ctx context.Context, reg *registrydomain.Registry) {
	evictor, ok := c.discovery.(discoveryEvictor)
	if !ok || reg == nil {
		return
	}
	for _, kind := range discoveryKinds {
		// The prefix covers the per-URL keys a server with URL variables adds.
		if key, cacheable := discoveryKey(ctx, reg, kind); cacheable {
			evictor.DeleteByPrefix(key)
		}
	}
}

// fixableByConnecting reports a refusal somebody can clear from outside, by
// connecting an account.
//
// The negative cache exists to stop a broken upstream being hammered for ten
// seconds. A missing account is not a broken upstream: the moment it is
// connected the next call would work, and remembering the refusal would keep
// failing for ten seconds after the person did exactly what they were told —
// with nothing in the answer to say that waiting is what is left.
//
// Both shapes count. A ConsentRequiredError names a page the caller walks
// themselves; an ApplicationNotConnectedError names one they cannot, because
// the account belongs to the server's instance or to an end user they have not
// named. Which of the two it is changes who acts, not how soon it takes effect.
func fixableByConnecting(err error) bool {
	var consentErr *ConsentRequiredError
	if errors.As(err, &consentErr) {
		return true
	}
	var notConnected *ApplicationNotConnectedError
	return errors.As(err, &notConnected)
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
	p := identity.PrincipalFromContext(ctx)
	if p == nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(p.Issuer + "|" + p.Subject))
	return key + ":" + hex.EncodeToString(sum[:8]), true
}
