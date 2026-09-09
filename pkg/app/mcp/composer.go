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
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"golang.org/x/sync/singleflight"
)

//go:generate mockery --name=Composer --dir=. --output=./mocks --filename=mcp_composer_mock.go --case=underscore --with-expecter
type Composer interface {
	ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error)
	CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error)
	ListResources(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Resource, error)
	ListResourceTemplates(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]ResourceTemplate, error)
	ReadResource(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, error)
	ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Prompt, error)
	GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error)
	// ToolInventory reports the surface server by server, including the servers
	// ListTools has to leave out because they are serving nothing yet.
	ToolInventory(ctx context.Context, rc *appconsumer.RoutableConsumer) (*ToolInventory, error)
}

var _ Composer = (*composer)(nil)

type composer struct {
	dialer    Dialer
	creds     CredentialResolver
	discovery DiscoveryCache
	urlvars   URLValueResolver
	flight    singleflight.Group
	logger    *slog.Logger
}

// ComposerOption configures optional composer collaborators without widening the
// constructor for the common case.
type ComposerOption func(*composer)

// WithURLValues wires the resolver that fills a registry's per-user URL
// placeholders (e.g. {account_url}) from the calling principal's install before
// dialing. Omitted, servers that declare URL variables cannot be reached.
func WithURLValues(r URLValueResolver) ComposerOption {
	return func(c *composer) { c.urlvars = r }
}

func NewComposer(dialer Dialer, creds CredentialResolver, discovery DiscoveryCache, logger *slog.Logger, opts ...ComposerOption) Composer {
	c := &composer{
		dialer:    dialer,
		creds:     creds,
		discovery: discovery,
		logger:    logger,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type binding struct {
	registry *registrydomain.Registry
	tool     Tool
	exposed  string
}

func (c *composer) ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error) {
	annotateTargets(ctx, len(mcpRegistries(rc)))
	// Partial federation: upstreams still awaiting consent are skipped and the
	// linked ones are listed. Only when every upstream needs consent does
	// compose report it, so the client is told to visit the connect page.
	comp, err := c.compose(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]Tool, 0, len(comp.bindings))
	for _, b := range comp.bindings {
		t := attributeTool(b.tool, b.registry)
		t.Name = b.exposed
		out = append(out, t)
	}
	return out, nil
}

func (c *composer) CallTool(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error) {
	comp, err := c.compose(ctx, rc)
	if err != nil {
		return nil, err
	}
	for _, b := range comp.bindings {
		if b.exposed != name {
			continue
		}
		stop := annotateUpstream(ctx, b.registry, b.tool.Name)
		defer stop()
		return invokeUpstream(c, ctx, rc, b.registry, func(up Upstream) (json.RawMessage, error) {
			return up.CallTool(ctx, b.tool.Name, arguments)
		})
	}
	// The upstream offers this tool but the consumer's toolkit excludes it: a
	// policy denial, and the answer must say so. Connecting an account would not
	// change it, so this is checked before any pending consent — otherwise a
	// forbidden tool sends the user off to an authorization flow that cannot
	// grant it.
	if _, forbidden := comp.denied[name]; forbidden {
		return nil, &ToolNotPermittedError{Tool: name}
	}
	// No reachable upstream exposes this tool. If another upstream is still
	// awaiting consent it may be the one that owns the tool, so the consent
	// requirement is the useful answer; otherwise the tool genuinely does not
	// exist. A tool served by a reachable upstream never reaches this point, so
	// an unconnected provider can no longer break calls routed elsewhere.
	if comp.consent != nil {
		return nil, comp.consent
	}
	return nil, fmt.Errorf("%w: %s", ErrToolNotFound, name)
}

// annotateUpstream records the resolved upstream registry on the active MCP
// span and returns a stop function that captures the upstream call latency.
func annotateUpstream(ctx context.Context, reg *registrydomain.Registry, upstreamTool string) func() {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return func() {}
	}
	var host, catalog, transport string
	if reg.MCPTarget != nil {
		host = hostFromURL(reg.MCPTarget.URL)
		catalog = reg.MCPTarget.Code
		transport = string(reg.MCPTarget.Transport)
	}
	span.SetMCPUpstream(reg.Name, reg.ID.String(), host, catalog, transport, upstreamTool)
	start := time.Now()
	return func() { span.SetLatency(time.Since(start)) }
}

func annotateTargets(ctx context.Context, count int) {
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPTargets(count)
	}
}

func hostFromURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// serverSurface is one bound MCP server's contribution to a request: the tool
// bindings it offered after the consumer's toolkit had its say, the tool names
// that toolkit turned away, or why the server offered nothing at all. Both the
// federated surface (compose) and the inventory meta-tool read these, so the
// list a caller is shown and the tools it can actually call come from one
// discovery pass and can never disagree.
type serverSurface struct {
	registry *registrydomain.Registry
	bindings []binding
	denied   []string
	// policy is what the consumer's toolkit permits on this server. It is known
	// whether or not the server answered, which is what lets a caller be told
	// what an unreachable server would offer without overstating it.
	policy toolPolicy
	// consent is set when the server is waiting for this principal to connect
	// their account: it holds no tools yet, and connecting is what changes that.
	consent *ConsentRequiredError
	// err is any other reason discovery failed (unreachable, misconfigured).
	err error
}

// serverSurfaces discovers every bound upstream once and reports each one's
// outcome, without deciding what to do about a failure — that is the caller's
// call, since federation degrades differently from an inventory. Only a
// cancelled context aborts.
func (c *composer) serverSurfaces(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	registries []*registrydomain.Registry,
) ([]serverSurface, error) {
	toolkit := rc.Consumer.Toolkit()
	out := make([]serverSurface, 0, len(registries))
	for _, found := range c.discoverTools(ctx, rc, registries) {
		reg, tools := found.registry, found.items
		surface := serverSurface{registry: reg, policy: toolkitPolicy(toolkit, reg)}
		if err := found.err; err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(err, &consentErr) {
				surface.consent = consentErr
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
			} else {
				surface.err = err
			}
			out = append(out, surface)
			continue
		}
		surface.bindings = selectTools(toolkit, reg, tools)
		if toolkit != nil {
			allowed := make(map[string]struct{}, len(surface.bindings))
			for _, b := range surface.bindings {
				allowed[b.tool.Name] = struct{}{}
			}
			for _, t := range tools {
				if _, ok := allowed[t.Name]; !ok {
					surface.denied = append(surface.denied, t.Name)
				}
			}
		}
		out = append(out, surface)
	}
	return out, nil
}

// compose discovers every upstream bound to the consumer and returns the tool
// bindings of the reachable ones. An upstream awaiting user consent never
// aborts the composition — it is skipped so the linked upstreams still federate
// — and its consent requirement is reported separately so each caller can
// decide whether it is relevant: listing ignores it, calling a tool no reachable
// upstream serves reports it. Only when nothing at all could be composed does it
// become the returned error.
func (c *composer) compose(ctx context.Context, rc *appconsumer.RoutableConsumer) (*composition, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	surfaces, err := c.serverSurfaces(ctx, rc, registries)
	if err != nil {
		return nil, err
	}
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed

	var candidates []binding
	var pendingConsent *ConsentRequiredError
	// firstSkipped is the reason the first fail-open skip gave. It matters only
	// when nothing at all was reachable: there is no healthy surface left to
	// protect, so the caller is better served by the real cause — a
	// misconfiguration like an upstream that reuses the caller's token — than by
	// a bare "unreachable".
	var firstSkipped error
	denied := make(map[string]struct{})
	reachable := 0
	for _, surface := range surfaces {
		reg := surface.registry
		if surface.consent != nil {
			// Partial consent is allowed on the connect page — skip unlinked
			// upstreams during federation and serve tools from linked ones.
			if pendingConsent == nil {
				pendingConsent = surface.consent
			}
			continue
		}
		if surface.err != nil {
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, surface.err)
			}
			if firstSkipped == nil {
				firstSkipped = fmt.Errorf("registry %q: %w", reg.Name, surface.err)
			}
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", surface.err)
			continue
		}
		reachable++
		candidates = append(candidates, surface.bindings...)
		// Remember what the toolkit turned away. A call for one of these is a
		// policy denial, and answering it with "not found" — or worse, with a
		// consent prompt for an unrelated upstream — hides the real reason.
		for _, name := range surface.denied {
			denied[name] = struct{}{}
		}
	}
	if reachable == 0 {
		// Nothing could be composed. A pending consent requirement is the more
		// actionable explanation, so it wins over a bare "unreachable".
		if pendingConsent != nil {
			return nil, pendingConsent
		}
		if firstSkipped != nil {
			return nil, fmt.Errorf("%w: %w", ErrUpstreamUnavailable, firstSkipped)
		}
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	bindings := resolveNames(candidates)
	// A name that another registry ends up exposing was never really denied.
	for _, b := range bindings {
		delete(denied, b.exposed)
	}
	return &composition{bindings: bindings, denied: denied, consent: pendingConsent}, nil
}

// composition is the consumer's effective MCP surface for one request: the tool
// bindings it may use, the tools its toolkit turned away, and any upstream that
// is still awaiting user consent.
type composition struct {
	bindings []binding
	denied   map[string]struct{}
	consent  *ConsentRequiredError
}

// toolPolicy is what a consumer's toolkit permits on one server: everything the
// server offers, or an explicit set (possibly empty). The zero value permits
// everything, which is what a consumer with no toolkit gets.
type toolPolicy struct {
	restricted bool
	names      []string
}

func (p toolPolicy) permits(tool string) bool {
	if !p.restricted {
		return true
	}
	return slices.Contains(p.names, tool)
}

// toolkitPolicy reads off what the toolkit allows on one server, by the same
// rule selectTools applies to the tools it discovered: no toolkit allows
// everything, a wildcard entry allows everything this server offers, and named
// entries allow exactly those — a toolkit that names nothing for the server
// allowing nothing.
func toolkitPolicy(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry) toolPolicy {
	if toolkit == nil {
		return toolPolicy{}
	}
	entries := toolkit.EntriesFor(reg.ID)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Tool == consumerdomain.ToolWildcard {
			return toolPolicy{}
		}
		if e.Tool != "" {
			names = append(names, e.Tool)
		}
	}
	return toolPolicy{restricted: true, names: names}
}

func selectTools(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry, tools []Tool) []binding {
	if toolkit == nil {
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
			continue
		}
		t, ok := byName[e.Tool]
		if !ok {
			continue
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
	for _, e := range entries {
		if e.Tool != consumerdomain.ToolWildcard {
			continue
		}
		for _, t := range tools {
			if _, dup := seen[t.Name]; dup {
				continue
			}
			seen[t.Name] = struct{}{}
			out = append(out, binding{registry: reg, tool: t, exposed: t.Name})
		}
	}
	return out
}
