package consumer

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

// ToolWildcard selects every tool (or prompt) exposed by the upstream MCP
// server; on resource entries it selects every resource URI.
const ToolWildcard = "*"

// FailMode controls virtual-MCP behavior when an upstream MCP server is
// unreachable during tool discovery.
type FailMode string

const (
	// FailModeClosed rejects the request when any upstream is unreachable.
	FailModeClosed FailMode = "closed"
	// FailModeOpen serves the tools of the reachable upstreams.
	FailModeOpen FailMode = "open"
)

func (m FailMode) Validate() error {
	switch m {
	case "", FailModeClosed, FailModeOpen:
		return nil
	}
	return fmt.Errorf("%w: %q", ErrInvalidFailMode, m)
}

// ToolkitEntry grants a consumer access to one item of an attached MCP
// registry. Exactly one selector is set per entry:
//
//   - Tool: a tool name or "*", optionally renamed via ExposeAs.
//   - Prompt: a prompt name or "*", optionally renamed via ExposeAs.
//   - Resource: a resource URI, a prefix pattern ("repo://github/*"), or "*".
//     Resources are URI-addressed, so ExposeAs does not apply.
type ToolkitEntry struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Tool       string         `json:"tool,omitempty"`
	Prompt     string         `json:"prompt,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	ExposeAs   string         `json:"expose_as,omitempty"`
}

// selector returns the surface kind and value of the entry's single selector.
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

// Toolkit is the inline MCP authorization config of a consumer. An empty
// toolkit on an MCP consumer exposes every tool, prompt, and resource of
// every attached registry. A non-empty toolkit is an allowlist per surface:
// only the listed tools/prompts/resources are exposed, and a registry with no
// entries for a surface exposes nothing on that surface.
type Toolkit []ToolkitEntry

func (t Toolkit) Validate(known map[ids.RegistryID]struct{}) error {
	seen := make(map[string]struct{}, len(t))
	seenAliases := make(map[string]struct{}, len(t))
	for _, e := range t {
		if e.RegistryID.IsNil() {
			return fmt.Errorf("%w: nil registry_id", ErrInvalidToolkit)
		}
		if _, ok := known[e.RegistryID]; !ok {
			return fmt.Errorf("%w: registry %s is not attached to the consumer", ErrInvalidToolkit, e.RegistryID)
		}
		kind, value, err := e.selector()
		if err != nil {
			return err
		}
		key := e.RegistryID.String() + "/" + kind + "/" + value
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate %s %q for registry %s", ErrInvalidToolkit, kind, value, e.RegistryID)
		}
		seen[key] = struct{}{}
		if e.ExposeAs != "" {
			if kind == "resource" {
				return fmt.Errorf("%w: expose_as is not valid on resource entries (resources are URI-addressed)", ErrInvalidToolkit)
			}
			if value == ToolWildcard {
				return fmt.Errorf("%w: expose_as is not valid with the %q wildcard", ErrInvalidToolkit, ToolWildcard)
			}
			alias := strings.TrimSpace(e.ExposeAs)
			if alias == "" {
				return fmt.Errorf("%w: expose_as cannot be blank", ErrInvalidToolkit)
			}
			if _, dup := seenAliases[alias]; dup {
				return fmt.Errorf("%w: duplicate expose_as alias %q", ErrInvalidToolkit, alias)
			}
			seenAliases[alias] = struct{}{}
		}
	}
	return nil
}

// EntriesFor returns the tool entries that target the given registry.
func (t Toolkit) EntriesFor(registryID ids.RegistryID) []ToolkitEntry {
	return t.entriesFor(registryID, func(e ToolkitEntry) string { return e.Tool })
}

// PromptEntriesFor returns the prompt entries that target the given registry.
func (t Toolkit) PromptEntriesFor(registryID ids.RegistryID) []ToolkitEntry {
	return t.entriesFor(registryID, func(e ToolkitEntry) string { return e.Prompt })
}

// ResourceEntriesFor returns the resource entries that target the given registry.
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

// AllowsResource reports whether the toolkit exposes the given resource URI
// on the given registry. An empty toolkit allows everything.
func (t Toolkit) AllowsResource(registryID ids.RegistryID, uri string) bool {
	if len(t) == 0 {
		return true
	}
	for _, e := range t.ResourceEntriesFor(registryID) {
		if MatchResource(strings.TrimSpace(e.Resource), uri) {
			return true
		}
	}
	return false
}

// MatchResource matches a resource selector against a URI: exact match, the
// global wildcard "*", or a trailing-asterisk prefix ("repo://github/*").
func MatchResource(pattern, uri string) bool {
	if pattern == ToolWildcard {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(uri, prefix)
	}
	return pattern == uri
}
