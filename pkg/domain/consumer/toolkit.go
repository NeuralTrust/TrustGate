package consumer

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

// ToolWildcard selects every tool exposed by the upstream MCP server.
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

// ToolkitEntry grants a consumer access to one tool (or all tools) of an
// attached MCP registry, optionally renaming it on the virtual MCP surface.
type ToolkitEntry struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Tool       string         `json:"tool"`
	ExposeAs   string         `json:"expose_as,omitempty"`
}

// Toolkit is the inline MCP authorization config of a consumer. An empty
// toolkit on an MCP consumer exposes every tool of every attached registry.
type Toolkit []ToolkitEntry

func (t Toolkit) Validate(known map[ids.RegistryID]struct{}) error {
	seenTools := make(map[string]struct{}, len(t))
	seenAliases := make(map[string]struct{}, len(t))
	for _, e := range t {
		if e.RegistryID.IsNil() {
			return fmt.Errorf("%w: nil registry_id", ErrInvalidToolkit)
		}
		if _, ok := known[e.RegistryID]; !ok {
			return fmt.Errorf("%w: registry %s is not attached to the consumer", ErrInvalidToolkit, e.RegistryID)
		}
		tool := strings.TrimSpace(e.Tool)
		if tool == "" {
			return fmt.Errorf("%w: tool is required (use %q for all tools)", ErrInvalidToolkit, ToolWildcard)
		}
		key := e.RegistryID.String() + "/" + tool
		if _, dup := seenTools[key]; dup {
			return fmt.Errorf("%w: duplicate tool %q for registry %s", ErrInvalidToolkit, tool, e.RegistryID)
		}
		seenTools[key] = struct{}{}
		if e.ExposeAs != "" {
			if tool == ToolWildcard {
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

// EntriesFor returns the toolkit entries that target the given registry.
func (t Toolkit) EntriesFor(registryID ids.RegistryID) []ToolkitEntry {
	var out []ToolkitEntry
	for _, e := range t {
		if e.RegistryID == registryID {
			out = append(out, e)
		}
	}
	return out
}
