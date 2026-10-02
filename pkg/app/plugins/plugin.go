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

// ContentReader is the opt-in a plugin declares when it inspects the text of
// the request or response to reach a verdict (a moderation or scoring
// guardrail). It is what lets the planner sequence a same-priority parallel
// rewriter (MutatesRequestBody / MutatesResponseBody) ahead of it, so the
// reader judges the rewritten content instead of the original (RUN-1693).
//
// The default is false: a plugin that does not implement it, or that does not
// look at content (a rate limiter, a size limit), keeps its placement. A plugin
// that both rewrites and reads is treated as a rewriter.
type ContentReader interface {
	ReadsContent() bool
}

// IsContentReader reports whether the descriptor opted in as a content reader.
// Adding a plugin to that set is a scheduling decision, so the registry wiring
// test enumerates it and fails when the set changes unannounced.
func IsContentReader(d PluginDescriptor) bool {
	r, ok := d.(ContentReader)
	return ok && r.ReadsContent()
}

// LocalRewriter is the opt-in a body rewriter declares when the content it
// rewrites never leaves the gateway: no provider, no remote guard, only local
// rules (a regex mask, a template, a tool filter). The planner runs such a
// rewriter ahead of the rewriters of its priority that send the content to a
// third party, so a remote guard (bedrock_guardrail, google_model_armor,
// trustguard) is handed the masked text and not the raw one (RUN-1745).
//
// The default is false. A rewriter that does not implement it is treated as one
// that sends content off the box, which can only move it later, never hand it
// text a local mask was meant to hide. The flag has no effect on a plugin that
// does not rewrite the stage's body.
type LocalRewriter interface {
	RewritesLocally() bool
}

// RewritesLocally reports whether the descriptor opted in as a local rewriter.
// Like the content reader set, the registry wiring test enumerates it.
func RewritesLocally(d PluginDescriptor) bool {
	r, ok := d.(LocalRewriter)
	return ok && r.RewritesLocally()
}

// SettingsWriteValidator is implemented by plugins with rules that apply only
// when settings are written, never when a stored policy is loaded. It can
// reject a shape ValidateConfig must still accept, such as one saved before
// the rule existed.
//
// previous is the settings as they were stored immediately before this
// write: nil on create, and nil when the write also repoints the policy at a
// different plugin (a slug change), since settings from another plugin are
// not a previous version of this one's. A validator that wants to keep a
// pre-existing shape editable (RUN-1711's option "b": reject only a newly
// introduced unknown key) compares against previous; one with no such rule
// simply ignores it.
type SettingsWriteValidator interface {
	ValidateSettingsWrite(settings, previous map[string]any) error
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

// CredentialSettings is the opt-in a plugin declares to mark which
// dot-separated paths in its settings hold secrets. Settings is untyped
// (map[string]any), so nothing outside the plugin knows its shape; inferring
// secrecy from field names (anything matching key|secret|token|password) is
// deliberately not done: it fails silently, and toward exposure. The
// declaration lives with the plugin that owns the shape.
//
// A path walks nested settings objects: "credentials.access_key_id" reaches
// settings["credentials"].(map[string]any)["access_key_id"]. Declared paths
// are masked on every policy response and resolved on update (see
// api/handler/http/policy/response and app/policy).
type CredentialSettings interface {
	CredentialPaths() []string
}

// PluginCredentialPaths returns the settings paths slug declared as
// credential-bearing, and whether the slug is known at all.
//
// known is false for a nil registry or an unregistered slug: nothing is known
// about the shape of those settings, so a caller rendering them to a client
// must withhold them rather than assume they carry no secret. known is true
// with no paths for a registered plugin that declares none.
func PluginCredentialPaths(reg Registry, slug string) (paths []string, known bool) {
	if reg == nil {
		return nil, false
	}
	p, ok := reg.Get(slug)
	if !ok {
		return nil, false
	}
	c, ok := p.(CredentialSettings)
	if !ok {
		return nil, true
	}
	return c.CredentialPaths(), true
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
// accordingly. It is derived from the source of truth (Policy.GatewayWide, so a
// global or an MCP-wide placement, plus the resolved consumer), never from
// request headers, path or credentials.
type RuntimeScope struct {
	GatewayID  string
	ConsumerID string
	Global     bool
}

// Subject resolves the partition for this execution: gateway-wide when the
// policy is global or MCP-wide, otherwise the current consumer. It returns the
// dimension label ("global" or "consumer") and the identifier to key state on.
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
