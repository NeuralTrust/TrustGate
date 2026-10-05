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
	"fmt"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const maxLoggedToolName = 100

// PendingToolSink takes the tools a pinned registry listed that have no decision
// yet, so an admin can review them. Submit must not block and must not fail the
// caller: discovery never waits on it. AsyncPendingRecorder is the implementation.
type PendingToolSink interface {
	Submit(gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate)
}

// WithPendingToolSink wires where tools a pinned registry lists that are not
// decided yet go. Omitted, those tools are hidden but not recorded.
func WithPendingToolSink(s PendingToolSink) ComposerOption {
	return func(c *composer) { c.pending = s }
}

// screenAsk wraps one registry's upstream listing so that, for tools of a pinned
// registry, only approved definitions leave discovery. It runs before the result
// is cached (and inside the singleflight), so the cached list is already
// filtered, and tools/list and tools/call, which both go through discovery, see
// the same surface. Other kinds and auto registries are returned untouched.
func screenAsk[T any](
	c *composer,
	reg *registrydomain.Registry,
	kind string,
	ask func(context.Context) ([]T, error),
) func(context.Context) ([]T, error) {
	if kind != "tools" || !reg.ToolPolicy.IsPinned() {
		return ask
	}
	return func(ctx context.Context) ([]T, error) {
		items, err := ask(ctx)
		if err != nil {
			return items, err
		}
		tools, ok := any(items).([]Tool)
		if !ok {
			return items, nil
		}
		screened, ok := any(c.screenPinnedTools(reg, tools)).([]T)
		if !ok {
			return nil, fmt.Errorf("mcp discovery: unexpected tool list type %T", items)
		}
		return screened, nil
	}
}

// screenPinnedTools keeps the tools whose exact (name, fingerprint) the
// registry's snapshot set approves. Rejected, pending, unknown and changed
// definitions are hidden. Unknown ones are handed to the recorder in one call.
// A recorder failure never exposes anything: the filtered list is returned.
func (c *composer) screenPinnedTools(reg *registrydomain.Registry, tools []Tool) []Tool {
	decisions := reg.DecisionIndex()
	exposed := make([]Tool, 0, len(tools))
	var unknown []registrydomain.ToolCandidate
	for _, t := range tools {
		cand, err := ToolCandidate(t)
		if err != nil {
			c.logger.Warn("mcp composer: hiding tool with an invalid definition on a pinned registry",
				"registry_id", reg.ID.String(), "tool", truncateForLog(t.Name), "error", err)
			continue
		}
		status, decided := decisions[cand.ToolRef]
		switch {
		case !decided:
			unknown = append(unknown, cand)
		case status == registrydomain.ToolStatusApproved:
			exposed = append(exposed, t)
		}
	}
	if len(unknown) > 0 && c.pending != nil {
		// The decision belongs to the shelf registry, not to a per-install clone.
		c.pending.Submit(reg.GatewayID, reg.ScopeKey(), unknown)
	}
	return exposed
}

// ToolCandidate is the one place a listed tool becomes a (name, fingerprint)
// identity. The discovery filter and the admin API both call it on the Tool the
// same upstream client produced, so the fingerprint an admin approves is the one
// the data plane computes, whatever the client did to number literals on the way.
func ToolCandidate(t Tool) (registrydomain.ToolCandidate, error) {
	return registrydomain.NewToolCandidate(t.Name, t.Description(), t.InputSchema())
}

func truncateForLog(s string) string {
	if utf8.RuneCountInString(s) <= maxLoggedToolName {
		return s
	}
	return string([]rune(s)[:maxLoggedToolName]) + "..."
}

// pinSuffix is what a registry's tool policy and decided set add to a key or a
// fingerprint of its surface: nothing for an auto registry, so existing keys do
// not move, and the policy plus a hash of the decided set for a pinned one, so a
// decision, or a flip between auto and pinned, changes the surface even when
// the registry's updated_at does not move.
func pinSuffix(reg *registrydomain.Registry) string {
	if reg == nil || !reg.ToolPolicy.IsPinned() {
		return ""
	}
	return ":pin:" + pinnedSetHash(reg.PinnedTools)
}
