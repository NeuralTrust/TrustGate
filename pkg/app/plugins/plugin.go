package plugins

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
)

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
	Name() string
	// MandatoryStages are the stages the plugin always runs on, regardless of
	// the policy configuration. They must be a subset of SupportedStages.
	MandatoryStages() []policy.Stage
	// SupportedStages are every stage the plugin can run on. A policy may opt
	// into any subset of these; mandatory stages are always included.
	SupportedStages() []policy.Stage
	SupportedModes() []policy.Mode
	ValidateConfig(settings map[string]any) error
	Execute(ctx context.Context, in ExecInput) (*Result, error)
}

// ExecInput is the immutable input handed to a plugin for a single stage run.
type ExecInput struct {
	Stage    policy.Stage
	Mode     policy.Mode
	Config   policy.PluginConfig
	Request  *infracontext.RequestContext
	Response *infracontext.ResponseContext
	// Event is the per-invocation metrics sink. It is nil when plugin traces
	// are disabled, so plugins must nil-check before using it.
	Event *metrics.EventContext
}

// Result carries the changes a plugin wants the executor to apply. Headers are
// merged into the response; a StopUpstream result short-circuits the chain and
// returns Body/StatusCode to the client without contacting the registry.
type Result struct {
	StatusCode   int
	Body         []byte
	Headers      map[string][]string
	StopUpstream bool
}
