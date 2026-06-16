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

package consumer

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

const ToolWildcard = "*"

type FailMode string

const (
	FailModeClosed FailMode = "closed"
	FailModeOpen   FailMode = "open"
)

func (m FailMode) Validate() error {
	switch m {
	case "", FailModeClosed, FailModeOpen:
		return nil
	}
	return fmt.Errorf("%w: %q", ErrInvalidFailMode, m)
}

type ToolkitEntry struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Tool       string         `json:"tool,omitempty"`
	Prompt     string         `json:"prompt,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	ExposeAs   string         `json:"expose_as,omitempty"`
}

func (e ToolkitEntry) selector() (kind, value string, err error) {
	set := 0
	if v := strings.TrimSpace(e.Tool); v != "" {
		kind, value, set = "tool", v, set+1
	}
	if v := strings.TrimSpace(e.Prompt); v != "" {
		kind, value, set = "prompt", v, set+1
	}
	if v := strings.TrimSpace(e.Resource); v != "" {
		kind, value, set = "resource", v, set+1
	}
	if set != 1 {
		return "", "", fmt.Errorf("%w: exactly one of tool, prompt, or resource is required per entry (use %q for all)",
			ErrInvalidToolkit, ToolWildcard)
	}
	return kind, value, nil
}

type Toolkit []ToolkitEntry

func (t Toolkit) Validate(known map[ids.RegistryID]struct{}) error {
	seen := make(map[string]struct{}, len(t))
	seenAliases := make(map[string]string, len(t))
	plainNames := map[string]map[string]struct{}{"tool": {}, "prompt": {}}
	for i := range t {
		e := &t[i]
		if e.RegistryID.IsNil() {
			return fmt.Errorf("%w: nil registry_id", ErrInvalidToolkit)
		}
		if _, ok := known[e.RegistryID]; !ok {
			return fmt.Errorf("%w: registry %s is not attached to the consumer", ErrInvalidToolkit, e.RegistryID)
		}
		if e.ExposeAs != "" && strings.TrimSpace(e.ExposeAs) == "" {
			return fmt.Errorf("%w: expose_as cannot be blank", ErrInvalidToolkit)
		}
		e.Tool = strings.TrimSpace(e.Tool)
		e.Prompt = strings.TrimSpace(e.Prompt)
		e.Resource = strings.TrimSpace(e.Resource)
		e.ExposeAs = strings.TrimSpace(e.ExposeAs)
		kind, value, err := e.selector()
		if err != nil {
			return err
		}
		if kind == "resource" {
			if err := validateResourcePattern(value); err != nil {
				return err
			}
		}
		key := e.RegistryID.String() + "/" + kind + "/" + value
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate %s %q for registry %s", ErrInvalidToolkit, kind, value, e.RegistryID)
		}
		seen[key] = struct{}{}
		if value != ToolWildcard && kind != "resource" {
			plainNames[kind][value] = struct{}{}
		}
		if e.ExposeAs != "" {
			if kind == "resource" {
				return fmt.Errorf("%w: expose_as is not valid on resource entries (resources are URI-addressed)", ErrInvalidToolkit)
			}
			if value == ToolWildcard {
				return fmt.Errorf("%w: expose_as is not valid with the %q wildcard", ErrInvalidToolkit, ToolWildcard)
			}
			if _, dup := seenAliases[e.ExposeAs]; dup {
				return fmt.Errorf("%w: duplicate expose_as alias %q", ErrInvalidToolkit, e.ExposeAs)
			}
			seenAliases[e.ExposeAs] = kind
		}
	}
	for alias, kind := range seenAliases {
		if _, taken := plainNames[kind][alias]; taken {
			return fmt.Errorf("%w: expose_as alias %q collides with another %s entry of the same name",
				ErrInvalidToolkit, alias, kind)
		}
	}
	return nil
}

func validateResourcePattern(pattern string) error {
	if pattern == ToolWildcard {
		return nil
	}
	if idx := strings.Index(pattern, "*"); idx >= 0 && idx != len(pattern)-1 {
		return fmt.Errorf("%w: resource pattern %q is unsupported (only a trailing * wildcard is allowed)",
			ErrInvalidToolkit, pattern)
	}
	return nil
}

func (t Toolkit) EntriesFor(registryID ids.RegistryID) []ToolkitEntry {
	return t.entriesFor(registryID, func(e ToolkitEntry) string { return e.Tool })
}

func (t Toolkit) PromptEntriesFor(registryID ids.RegistryID) []ToolkitEntry {
	return t.entriesFor(registryID, func(e ToolkitEntry) string { return e.Prompt })
}

func (t Toolkit) ResourceEntriesFor(registryID ids.RegistryID) []ToolkitEntry {
	return t.entriesFor(registryID, func(e ToolkitEntry) string { return e.Resource })
}

func (t Toolkit) entriesFor(registryID ids.RegistryID, selector func(ToolkitEntry) string) []ToolkitEntry {
	var out []ToolkitEntry
	for _, e := range t {
		if e.RegistryID == registryID && strings.TrimSpace(selector(e)) != "" {
			out = append(out, e)
		}
	}
	return out
}

func (t Toolkit) AllowsResource(registryID ids.RegistryID, uri string) bool {
	if t == nil {
		return true
	}
	for _, e := range t.ResourceEntriesFor(registryID) {
		if MatchResource(strings.TrimSpace(e.Resource), uri) {
			return true
		}
	}
	return false
}

func MatchResource(pattern, uri string) bool {
	if pattern == ToolWildcard {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(uri, prefix)
	}
	return pattern == uri
}
