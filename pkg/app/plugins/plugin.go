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

package plugins

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

// PluginDescriptor is the static contract of a plugin: its identity, the
// stages and modes it declares, the response dimensions it mutates, and its
// configuration validation. Consumers that only inspect plugin metadata
// (catalog building, stage planning, registration checks) depend on this
// rather than the full executable Plugin.
type PluginDescriptor interface {
	Name() string
	// MandatoryStages are the stages the plugin always runs on, regardless of
	// the policy configuration. They must be a subset of SupportedStages.
	MandatoryStages() []policy.Stage
	// SupportedStages are every stage the plugin can run on. A policy may opt
	// into any subset of these; mandatory stages are always included.
	SupportedStages() []policy.Stage
	SupportedModes() []policy.Mode
	SupportedProtocols() []Protocol
	ValidateConfig(settings map[string]any) error
	MutatesRequestBody() bool
	MutatesResponseBody() bool
	MutatesMetadata() bool
}

// ScopeInertSafe is the opt-in a plugin declares to keep running on a plane
// where the policy's mcp_scope does not gate. A plugin that resolves tool or
// registry names — reading Metadata["mcp.tool"] or Metadata["mcp.registry_id"],
// or carrying tool names in its settings — must return false: outside MCP
// there is no (registry, native tool) binding, so matching by name is wrong
// rather than degraded.
//
// Answered for RUN-1621: trustguard and request_size_limiter opted in, because
// each gates on something every plane has — the content of the request, and its
// size — and resolves no name that only exists inside MCP. tool_allowlist and
// per_tool_rate_limiter stay out by their own nature, and a policy of theirs
// narrowed by group alone is still refused with a 422 that names the plugin.
// Anything added later starts denied: the opt-in is per plugin, never blanket.
type ScopeInertSafe interface {
	ScopeInertSafe() bool
}

// inertSafe reports whether the descriptor opted in. A descriptor that does not
// implement ScopeInertSafe is denied, so no plugin turns cross-plane by
// omission.
func inertSafe(d PluginDescriptor) bool {
	s, ok := d.(ScopeInertSafe)
	return ok && s.ScopeInertSafe()
}

// Previewable is the opt-in a plugin declares to be runnable against a sample
// request from the console, outside any gateway traffic. It may only be declared
// by a plugin whose Execute is pure: no database, cache, network call or shared
// counter, and no dependency on anything the preview cannot supply. A plugin that
// rate-limits, calls a provider or writes to a collector must not declare it —
// previewing it would either mutate real state or answer with something the real
// request would not.
//
// The preview drives the plugin at pre_request only, with a nil Event and a zero
// RuntimeScope, and reports a rewritten body or a rejection. A plugin that needs a
// stage, a scope subject or an event sink must not opt in.
//
// Answered for RUN-1640: prompt_template opted in, because it reads only its own
// settings, the request body and the request headers, and returns the rewritten
// body. Anything added later starts denied: the opt-in is per plugin, never
// blanket.
type Previewable interface {
	Previewable() bool
}

// previewable reports whether the descriptor opted in. A descriptor that does not
// implement Previewable is denied, so no plugin becomes previewable by omission.
func previewable(d PluginDescriptor) bool {
	p, ok := d.(Previewable)
	return ok && p.Previewable()
}

// IsInertSafe reports whether the plugin registered under slug opted into
// running on a plane where the scope does not gate. It is the same predicate
// inertSafe applies, reachable from the config load path so the decision has a
// single implementation. An absent registry or an unknown slug is denied.
func IsInertSafe(reg Registry, slug string) bool {
	if reg == nil {
		return false
	}
	p, ok := reg.Get(slug)
	if !ok {
		return false
	}
	return inertSafe(p)
}

// Plugin is a single unit of request/response processing. Each plugin declares
// the fixed stages it runs on via Stages; the executor drives it only at those
// stages and ignores the stage recorded in the policy configuration.
//
// Plugins must treat the request and response contexts as read-only and return
// every mutation through Result so the executor can apply them deterministically
// even when a stage runs plugins concurrently.
//
//go:generate mockery --name=Plugin --dir=. --output=./mocks --filename=plugin_mock.go --case=underscore --with-expecter
type Plugin interface {
	PluginDescriptor
	Execute(ctx context.Context, in ExecInput) (*Result, error)
}

// ExecInput is the immutable input handed to a plugin for a single stage run.
type ExecInput struct {
	Stage    policy.Stage
	Mode     policy.Mode
	Config   policy.PluginConfig
	Scope    RuntimeScope
	Request  *infracontext.RequestContext
	Response *infracontext.ResponseContext
	// Event is the per-invocation metrics sink. It is nil when plugin traces
	// are disabled, so plugins must nil-check before using it.
	Event *metrics.EventContext
}

// RuntimeScope is the execution scope derived from the policy and the resolved
// consumer. It tells a plugin whether the policy applies gateway-wide (Global)
// or to a single consumer, so stateful plugins can partition their state
// accordingly. It is derived from the source of truth (Policy.Global plus the
// resolved consumer), never from request headers, path or credentials.
type RuntimeScope struct {
	GatewayID  string
	ConsumerID string
	Global     bool
}

// Subject resolves the partition for this execution: gateway-wide when the
// policy is global, otherwise the current consumer. It returns the dimension
// label ("global" or "consumer") and the identifier to key state on.
func (s RuntimeScope) Subject() (dimension string, id string, err error) {
	if s.Global {
		if s.GatewayID == "" {
			return "", "", errors.New("plugins: missing gateway id for global scope")
		}
		return "global", s.GatewayID, nil
	}
	if s.ConsumerID == "" {
		return "", "", errors.New("plugins: missing consumer id for consumer scope")
	}
	return "consumer", s.ConsumerID, nil
}

// Result carries the changes a plugin wants the executor to apply. Headers are
// merged into the response; a StopUpstream result short-circuits the chain and
// returns Body/StatusCode to the client without contacting the registry.
type Result struct {
	StatusCode   int
	Body         []byte
	RequestBody  []byte
	Headers      map[string][]string
	StopUpstream bool
}
