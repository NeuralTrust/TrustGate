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
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func (c *composer) ListPrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]Prompt, error) {
	bindings, err := c.composePrompts(ctx, rc)
	if err != nil {
		return nil, err
	}
	out := make([]Prompt, 0, len(bindings))
	for _, b := range bindings {
		p := b.prompt
		p.Name = b.exposed
		out = append(out, p)
	}
	return out, nil
}

func (c *composer) GetPrompt(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments map[string]string) (json.RawMessage, error) {
	bindings, err := c.composePrompts(ctx, rc)
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
		return up.GetPrompt(ctx, b.prompt.Name, arguments)
	}
	return nil, fmt.Errorf("%w: %s", ErrPromptNotFound, name)
}

type promptBinding struct {
	registry *registrydomain.Registry
	prompt   Prompt
	exposed  string
}

func (c *composer) composePrompts(ctx context.Context, rc *appconsumer.RoutableConsumer) ([]promptBinding, error) {
	registries := mcpRegistries(rc)
	if len(registries) == 0 {
		return nil, ErrNoMCPRegistries
	}
	failOpen := rc.Consumer.FailMode() == consumerdomain.FailModeOpen
	toolkit := rc.Consumer.Toolkit()

	var candidates []promptBinding
	reachable := 0
	for _, reg := range registries {
		prompts, err := discoverCached(c, ctx, rc, reg, "prompts", func(ctx context.Context, up Upstream) ([]Prompt, error) {
			return up.ListPrompts(ctx)
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
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
	if reachable == 0 {
		return nil, fmt.Errorf("%w: no upstream MCP server reachable", ErrUpstreamUnavailable)
	}
	items := make([]exposedName, len(candidates))
	for i, b := range candidates {
		items[i] = exposedName{name: b.exposed, registry: b.registry.Name, registryID: b.registry.ID.String()}
	}
	for i, name := range resolveExposedNames(items) {
		candidates[i].exposed = name
	}
	return candidates, nil
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
