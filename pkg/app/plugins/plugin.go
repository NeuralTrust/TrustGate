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
	ValidateConfig(settings map[string]any) error
	MutatesRequestBody() bool
	MutatesResponseBody() bool
	MutatesMetadata() bool
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
