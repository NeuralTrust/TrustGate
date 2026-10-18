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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func (c *composer) ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Prompt, error) {
	annotateTargets(ctx, len(mcpRegistries(rc)))
	// Same partial-federation contract as ListTools: upstreams awaiting consent
	// are skipped and the linked ones still answer, so a client refreshing its
	// surface never fails just because an optional provider is unconnected.
	comp, err := c.composePrompts(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]Prompt, 0, len(comp.bindings))
	for _, b := range comp.bindings {
		p := attributePrompt(b.prompt, b.registry)
		p.Name = b.exposed
		out = append(out, p)
	}
	return out, nil
}

func (c *composer) GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error) {
	comp, err := c.composePrompts(ctx, rc)
	if err != nil {
		return nil, err
	}
	for _, b := range comp.bindings {
		if b.exposed != name {
			continue
		}
		stop := annotateUpstream(ctx, b.registry, b.prompt.Name)
		defer stop()
		return invokeUpstream(c, ctx, rc, b.registry, func(up Upstream) (json.RawMessage, error) {
			return up.GetPrompt(ctx, b.prompt.Name, arguments)
		})
	}
	// Mirror CallTool: an upstream still awaiting an account may be the one
	// that owns this prompt, so what it is waiting on is the useful answer.
	if comp.pending != nil {
		return nil, comp.pending
	}
	return nil, fmt.Errorf("%w: %s", ErrPromptNotFound, name)
}

type promptBinding struct {
	registry *registrydomain.Registry
	prompt   Prompt
	exposed  string
}

// promptComposition is the prompts the reachable upstreams offer and, when an
// upstream served nothing because it is waiting on an account, what it waits
// on: a pending consent first, then a server with no account for this caller.
type promptComposition struct {
	bindings []promptBinding
	pending  error
}

func (c *composer) composePrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) (*promptComposition, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	// Same default as compose(): an absent or empty fail mode fails open, so
	// tools and prompts always degrade the same way for the same consumer.
	failOpen := rc.Consumer.FailMode() != consumerdomain.FailModeClosed
	toolkit := rc.Consumer.Toolkit()

	var candidates []promptBinding
	var pendingConsent *ConsentRequiredError
	var pendingNotConnected *ApplicationNotConnectedError
	reachable := 0
	for _, found := range discoverAll(c, ctx, rc, registries, "prompts", func(ctx context.Context, up Upstream) ([]Prompt, error) {
		return up.ListPrompts(ctx)
	}) {
		reg, prompts, err := found.registry, found.items, found.err
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var consentErr *ConsentRequiredError
			if errors.As(err, &consentErr) {
				// Partial consent is allowed on the connect page — skip unlinked
				// upstreams during federation and serve prompts from linked ones,
				// even when the consumer otherwise fails closed.
				if pendingConsent == nil {
					pendingConsent = consentErr
				}
				c.logger.Info("mcp composer: skipping upstream pending consent",
					"registry", reg.Name, "provider", consentErr.Provider)
				continue
			}
			// Same for a server with no account for this caller: what is
			// missing is an account, not the upstream.
			var notConnected *ApplicationNotConnectedError
			if errors.As(err, &notConnected) {
				if pendingNotConnected == nil {
					pendingNotConnected = notConnected
				}
				c.logger.Info("mcp composer: skipping upstream with no account for this caller",
					"registry", reg.Name, "provider", notConnected.Provider, "shared", notConnected.Shared)
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
		candidates = append(candidates, selectPrompts(toolkit, reg, prompts)...)
	}
	var pendingAccount error
	switch {
	case pendingConsent != nil:
		pendingAccount = pendingConsent
	case pendingNotConnected != nil:
		pendingAccount = pendingNotConnected
	}
	if reachable == 0 {
		if pendingAccount != nil {
			return nil, pendingAccount
		}
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	for i, b := range candidates {
		// Prompts stay on the original spelling. Version 2 drops a repeated
		// server prefix from tools only.
		candidates[i].exposed = exposedPromptName(b.exposed, b.registry)
	}
	return &promptComposition{bindings: candidates, pending: pendingAccount}, nil
}

// exposedPromptName is the original <server>_<prompt> spelling. Tool naming
// version 2 does not apply to prompts.
func exposedPromptName(name string, reg *registrydomain.Registry) string {
	e := exposedNameFor(name, reg)
	e.version = 0
	e.keepPrefix = false
	return e.String()
}

func selectPrompts(toolkit consumerdomain.Toolkit, reg *registrydomain.Registry, prompts []Prompt) []promptBinding {
	if toolkit == nil {
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
	byName := make(map[string]Prompt, len(prompts))
	for _, p := range prompts {
		byName[p.Name] = p
	}
	var out []promptBinding
	seen := make(map[string]struct{}, len(prompts))
	for _, e := range entries {
		if e.Prompt == consumerdomain.ToolWildcard {
			continue
		}
		p, ok := byName[e.Prompt]
		if !ok {
			continue
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
	for _, e := range entries {
		if e.Prompt != consumerdomain.ToolWildcard {
			continue
		}
		for _, p := range prompts {
			if _, dup := seen[p.Name]; dup {
				continue
			}
			seen[p.Name] = struct{}{}
			out = append(out, promptBinding{registry: reg, prompt: p, exposed: p.Name})
		}
	}
	return out
}
