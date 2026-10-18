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

// ResolvedTool is a tools/call target bound to the upstream that serves it:
// the registry to dial, the tool as the upstream names it, and the name the
// caller used. Resolving before the plugin chain runs fixes the destination, so
// a plugin that rewrites the request body can never reroute the call.
type ResolvedTool struct {
	Registry *registrydomain.Registry
	Tool     Tool
	Exposed  string
}

//go:generate mockery --name=Composer --dir=. --output=./mocks --filename=mcp_composer_mock.go --case=underscore --with-expecter
type Composer interface {
	ListTools(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Tool, error)
	// Resolve binds an exposed tool name to the registry that owns it. Ownership
	// is the server prefix of the name, decided before other registries are
	// dialed, so their consent and discovery errors cannot answer the call and
	// a connect ticket is minted only for the owner. Where two prefixes fit,
	// the owner is the one that serves the exact name tools/list publishes.
	// A name nobody owns answers *UnknownToolError (ErrToolNotFound). One the
	// toolkit turned away answers *ToolNotPermittedError. One whose server is
	// waiting on an account answers that server's *ConsentRequiredError or
	// *ApplicationNotConnectedError. One whose server is installed but
	// unreachable answers *ServerNotServingError.
	Resolve(ctx context.Context, rc *appconsumer.RoutableConsumer, name string) (*ResolvedTool, error)
	// Invoke calls a resolved tool on its owning upstream with the given
	// arguments.
	Invoke(ctx context.Context, rc *appconsumer.RoutableConsumer, target *ResolvedTool, arguments json.RawMessage) (json.RawMessage, error)
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
		if ClientAcceptsTypedOutput(ctx) {
			out = append(out, t)
			continue
		}
		if downgraded, dropped := withObjectOutputSchema(t); dropped {
			c.logger.Debug("mcp composer: dropped outputSchema the client revision cannot carry",
				"registry", b.registry.Name, "tool", b.tool.Name)
			t = downgraded
		}
		out = append(out, t)
	}
	return out, nil
}

func (c *composer) Resolve(ctx context.Context, rc *appconsumer.RoutableConsumer, name string) (*ResolvedTool, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	// The exposed name carries its server. Servers that do not fit its prefix
	// are not dialed: dialing them minted a connect ticket for whichever
	// installed server lacked a credential (ENG-2178).
	owners := registriesForExposedName(registries, name)
	// No server prefix. The name can still be an upstream's own name that the
	// toolkit turned away, recorded under that own name, so the servers that
	// answer are asked. A server that needs an account is not this name's
	// owner: the ask is a probe and must not mint a ticket.
	unscoped := len(owners) == 0
	if unscoped {
		owners = registries
	}
	// Several prefixes can fit one name. Discover every candidate without
	// minting, then keep the one whose tools/list name is exactly this. A
	// ticket is minted only once that owner is known, and only for them.
	probe := unscoped || len(owners) > 1
	discoverCtx := ctx
	if probe {
		discoverCtx = withResolveProbe(ctx)
	}
	surfaces, err := c.serverSurfaces(discoverCtx, rc, owners)
	if err != nil {
		return nil, err
	}
	var candidates []binding
	for _, surface := range surfaces {
		if surface.serves() {
			candidates = append(candidates, surface.bindings...)
		}
	}
	// More than one published binding for this name is not a choice between
	// them. The first one used to win, which is how a copied suffix was
	// invoked. The call is refused before any consent ticket is minted.
	chosen, ok, err := matchExposed(resolveNames(candidates, owners), name)
	if err != nil {
		return nil, err
	}
	if ok {
		return &ResolvedTool{Registry: chosen.registry, Tool: chosen.tool, Exposed: chosen.exposed}, nil
	}
	if unscoped {
		if denied(surfaces, name) {
			return nil, &ToolNotPermittedError{Tool: name}
		}
		return nil, &UnknownToolError{Name: name}
	}
	// Nobody who answered serves this exact name. The longest prefix is the
	// server the name was written for; a shorter one that answered without the
	// tool does not take its denial or its consent.
	longest := longestPrefixSurfaces(surfaces, name)
	if denied(longest, name) {
		return nil, &ToolNotPermittedError{Tool: name}
	}
	var unavailable *ServerNotServingError
	for _, surface := range longest {
		if surface.consent != nil {
			if probe {
				return nil, c.mintedConsent(ctx, rc, surface.registry, name)
			}
			return nil, surface.consent
		}
		if surface.notConnected != nil {
			return nil, surface.notConnected
		}
		if surface.err != nil && unavailable == nil {
			// The dial error stays in the log. It can name a URL, and the
			// caller is told which server and which state, not that detail.
			c.logger.Warn("mcp composer: owning upstream unavailable",
				"registry", surface.registry.Name, "error", surface.err)
			unavailable = &ServerNotServingError{
				Server: inventoryServerName(surface.registry),
				State:  InventoryStateUnavailable,
			}
		}
	}
	if unavailable != nil {
		return nil, unavailable
	}
	return nil, &UnknownToolError{Name: name}
}

// matchExposed returns the single binding published under name. A second
// match is Unknown tool: callers map that to JSON-RPC -32602, and Resolve
// returns it before the consent path, so neither side is minted a ticket.
func matchExposed(bindings []binding, name string) (binding, bool, error) {
	var found binding
	seen := false
	for _, b := range bindings {
		if b.exposed != name {
			continue
		}
		if seen {
			return binding{}, false, &UnknownToolError{Name: name}
		}
		found = b
		seen = true
	}
	return found, seen, nil
}

// denied reports whether a serving surface turned this exact name away. A
// toolkit denial outranks a pending consent: connecting an account cannot
// grant a tool the consumer is not allowed to use.
func denied(surfaces []serverSurface, name string) bool {
	for _, surface := range surfaces {
		if !surface.serves() {
			continue
		}
		for _, native := range surface.denied {
			if native == name || exposedNameFor(native, surface.registry).String() == name {
				return true
			}
		}
	}
	return false
}

// longestPrefixSurfaces keeps the surfaces whose server prefix is the longest
// fit for name. Equal lengths all stay, in the order the registries were given.
func longestPrefixSurfaces(surfaces []serverSurface, name string) []serverSurface {
	best := 0
	var out []serverSurface
	for _, surface := range surfaces {
		n := matchedPrefixLen(surface.registry, name)
		if n == 0 || n < best {
			continue
		}
		if n > best {
			out = nil
			best = n
		}
		out = append(out, surface)
	}
	return out
}

// mintedConsent repeats discovery of one owner outside a resolve probe, so the
// consent the probe withheld grows the connect ticket the caller is about to
// be shown. The probe itself must not mint: a longer prefix that does not
// serve the name is asked only to be ruled out.
func (c *composer) mintedConsent(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, name string) error {
	again, err := c.serverSurfaces(ctx, rc, []*registrydomain.Registry{reg})
	if err != nil {
		return err
	}
	if len(again) == 1 {
		surface := again[0]
		if surface.consent != nil {
			return surface.consent
		}
		if surface.notConnected != nil {
			return surface.notConnected
		}
		if surface.err != nil {
			c.logger.Warn("mcp composer: owning upstream unavailable",
				"registry", surface.registry.Name, "error", surface.err)
			return &ServerNotServingError{
				Server: inventoryServerName(surface.registry),
				State:  InventoryStateUnavailable,
			}
		}
	}
	return &UnknownToolError{Name: name}
}

func (c *composer) Invoke(ctx context.Context, rc *appconsumer.RoutableConsumer, target *ResolvedTool, arguments json.RawMessage) (json.RawMessage, error) {
	if target == nil || target.Registry == nil {
		return nil, fmt.Errorf("%w: unresolved tool", ErrToolNotFound)
	}
	stop := annotateUpstream(ctx, target.Registry, target.Tool.Name)
	defer stop()
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPToolRisk(target.Tool.Risk())
	}
	out, err := invokeUpstream(c, ctx, rc, target.Registry, func(up Upstream) (json.RawMessage, error) {
		return up.CallTool(ctx, target.Tool.Name, arguments)
	})
	if fixableByConnecting(err) {
		c.forgetDiscovery(ctx, target.Registry)
	}
	if err != nil || ClientAcceptsTypedOutput(ctx) {
		return out, err
	}
	return withObjectStructuredContent(out), nil
}

// annotateUpstream records the resolved upstream registry on the active MCP
// span and returns a stop function that captures the upstream call latency.
func annotateUpstream(ctx context.Context, reg *registrydomain.Registry, upstreamTool string) func() {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return func() {}
	}
	annotateRegistry(span, reg, upstreamTool)
	start := time.Now()
	return func() { span.SetLatency(time.Since(start)) }
}

func annotateRegistry(span *trace.Span, reg *registrydomain.Registry, upstreamTool string) {
	if reg == nil {
		return
	}
	var host, catalog, transport string
	if reg.MCPTarget != nil {
		host = hostFromURL(reg.MCPTarget.URL)
		catalog = reg.MCPTarget.Code
		transport = string(reg.MCPTarget.Transport)
	}
	span.SetMCPUpstream(reg.Name, reg.ID.String(), host, catalog, transport, upstreamTool)
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
	// notConnected is set when the server has no account for this caller and
	// this caller cannot connect one: its instance's shared account is not
	// connected, or it keeps one per person and the request named nobody. It
	// is waiting on someone like consent is, not broken like err.
	notConnected *ApplicationNotConnectedError
	// err is any other reason discovery failed (unreachable, misconfigured).
	err error
}

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
			if consentErr, ok := errors.AsType[*ConsentRequiredError](err); ok {
				surface.consent = consentErr
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
			} else if notConnected, ok := errors.AsType[*ApplicationNotConnectedError](err); ok {
				surface.notConnected = notConnected
				c.logger.Info("mcp composer: skipping upstream with no account for this caller",
					"registry", reg.Name, "provider", notConnected.Provider, "shared", notConnected.Shared)
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
	var pendingNotConnected *ApplicationNotConnectedError

	var firstSkipped error
	denied := make(map[string]struct{})
	reachable := 0
	for _, surface := range surfaces {
		reg := surface.registry
		if surface.consent != nil {
			if pendingConsent == nil {
				pendingConsent = surface.consent
			}
			continue
		}
		// Skipped like a pending consent, and for the same reason: an account is
		// what is missing, so it is not an unreachable upstream, and a consumer
		// that fails closed must not refuse its whole surface over it.
		if surface.notConnected != nil {
			if pendingNotConnected == nil {
				pendingNotConnected = surface.notConnected
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
		for _, name := range surface.denied {
			denied[name] = struct{}{}
			denied[exposedNameFor(name, reg).String()] = struct{}{}
		}
	}
	if reachable == 0 {
		if pendingConsent != nil {
			return nil, pendingConsent
		}
		if pendingNotConnected != nil {
			return nil, pendingNotConnected
		}
		if firstSkipped != nil {
			return nil, fmt.Errorf("%w: %w", ErrUpstreamUnavailable, firstSkipped)
		}
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	bindings := resolveNames(candidates, registries)
	// A name that another registry ends up exposing was never really denied.
	for _, b := range bindings {
		delete(denied, b.exposed)
	}
	return &composition{bindings: bindings, denied: denied, consent: pendingConsent, notConnected: pendingNotConnected}, nil
}

type composition struct {
	bindings     []binding
	denied       map[string]struct{}
	consent      *ConsentRequiredError
	notConnected *ApplicationNotConnectedError
}

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
