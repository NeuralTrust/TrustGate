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
	"net/http"
	"net/url"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
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
		t := b.tool
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
		target, err := c.target(ctx, rc, b.registry)
		if err != nil {
			return nil, err
		}
		stop := annotateUpstream(ctx, b.registry, b.tool.Name)
		defer stop()
		up, err := c.dialer.Connect(ctx, target)
		if err != nil {
			return nil, err
		}
		defer up.Close(ctx)
		return up.CallTool(ctx, b.tool.Name, arguments)
	}
	// The upstream offers this tool but the consumer's toolkit excludes it: a
	// policy denial, and the answer must say so. Connecting an account would not
	// change it, so this is checked before any pending consent — otherwise a
	// forbidden tool sends the user off to an authorization flow that cannot
	// grant it.
	if _, forbidden := comp.denied[name]; forbidden {
		return nil, &RPCError{
			Code:       codePolicyBlocked,
			Message:    fmt.Sprintf("tool %q is not permitted for this consumer", name),
			HTTPStatus: http.StatusForbidden,
		}
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
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed
	toolkit := rc.Consumer.Toolkit()

	var candidates []binding
	var pendingConsent *ConsentRequiredError
	denied := make(map[string]struct{})
	reachable := 0
	for _, reg := range registries {
		tools, err := c.discover(ctx, rc, reg)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(err, &consentErr) {
				// Partial consent is allowed on the connect page — skip unlinked
				// upstreams during federation and serve tools from linked ones.
				if pendingConsent == nil {
					pendingConsent = consentErr
				}
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
				continue
			}
			if !failOpen {
				return nil, fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, reg.Name, err)
			}
			c.logger.Warn("mcp composer: skipping unreachable upstream",
				"registry", reg.Name, "error", err)
			continue
		}
		reachable++
		kept := selectTools(toolkit, reg, tools)
		candidates = append(candidates, kept...)
		// Remember what the toolkit turned away. A call for one of these is a
		// policy denial, and answering it with "not found" — or worse, with a
		// consent prompt for an unrelated upstream — hides the real reason.
		if toolkit != nil {
			allowed := make(map[string]struct{}, len(kept))
			for _, b := range kept {
				allowed[b.tool.Name] = struct{}{}
			}
			for _, t := range tools {
				if _, ok := allowed[t.Name]; !ok {
					denied[t.Name] = struct{}{}
				}
			}
		}
	}
	if reachable == 0 {
		// Nothing could be composed. A pending consent requirement is the more
		// actionable explanation, so it wins over a bare "unreachable".
		if pendingConsent != nil {
			return nil, pendingConsent
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
