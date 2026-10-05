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
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	// pendingRecordTimeout bounds one Record call. It is derived from the
	// discovery context, so a cancelled discovery cancels it too.
	pendingRecordTimeout = 5 * time.Second
	maxLoggedToolName    = 100
)

// PendingToolRecorder records tool definitions a pinned registry listed that have
// no decision yet, so an admin can review them. Implementations must be
// idempotent: the same candidate may be reported again by another pod or after
// the discovery cache expires.
type PendingToolRecorder interface {
	Record(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate) error
}

// WithPendingToolRecorder wires the sink for tools a pinned registry lists that
// are not decided yet. Omitted, those tools are hidden but not recorded.
func WithPendingToolRecorder(r PendingToolRecorder) ComposerOption {
	return func(c *composer) { c.pending = r }
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
		screened, _ := any(c.screenPinnedTools(ctx, reg, tools)).([]T)
		return screened, nil
	}
}

// screenPinnedTools keeps the tools whose exact (name, fingerprint) the
// registry's snapshot set approves. Rejected, pending, unknown and changed
// definitions are hidden. Unknown ones are handed to the recorder in one call.
// A recorder failure never exposes anything: the filtered list is returned.
func (c *composer) screenPinnedTools(ctx context.Context, reg *registrydomain.Registry, tools []Tool) []Tool {
	exposed := make([]Tool, 0, len(tools))
	var unknown []registrydomain.ToolCandidate
	for _, t := range tools {
		cand, err := registrydomain.NewToolCandidate(t.Name, t.Description(), t.InputSchema())
		if err != nil {
			c.logger.Warn("mcp composer: hiding tool with an invalid definition on a pinned registry",
				"registry_id", reg.ID.String(), "tool", truncateForLog(t.Name), "error", err)
			continue
		}
		if reg.IsToolApproved(cand.ToolRef) {
			exposed = append(exposed, t)
			continue
		}
		if !reg.HasToolDecision(cand.ToolRef) {
			unknown = append(unknown, cand)
		}
	}
	if len(unknown) > 0 && c.pending != nil {
		rctx, cancel := context.WithTimeout(ctx, pendingRecordTimeout)
		defer cancel()
		if err := c.pending.Record(rctx, reg.GatewayID, reg.ID, unknown); err != nil {
			c.logger.Warn("mcp composer: failed to record pending tools; they stay hidden",
				"registry_id", reg.ID.String(), "tools", len(unknown), "error", err)
			recordPendingToolError(ctx)
		}
	}
	return exposed
}

func truncateForLog(s string) string {
	if utf8.RuneCountInString(s) <= maxLoggedToolName {
		return s
	}
	return string([]rune(s)[:maxLoggedToolName]) + "..."
}

// recordPendingToolError counts a failed attempt to record pending tools of a
// pinned registry. The instrument is resolved per call: the SDK returns the same
// one for the same name and a failure is rare. No attributes: tenant and registry
// ids would be unbounded labels.
func recordPendingToolError(ctx context.Context) {
	counter, err := otel.Meter("trustgate/mcp").Int64Counter(
		"trustgate.mcp.pinned_tools.record_errors",
		metric.WithDescription("discoveries of a pinned registry that could not record their pending tools"),
	)
	if err != nil {
		slog.Warn("failed to create pinned tools record error counter", slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, 1)
}
