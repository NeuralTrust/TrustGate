package pluginiface

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

//go:generate mockery --name=Plugin --dir=. --output=./mocks --filename=plugin_mock.go --case=underscore --with-expecter
type Plugin interface {
	Name() string
	// Stages returns the fixed stages where the plugin must run.
	// If empty, the plugin will run on the stage specified in the config.
	Stages() []pluginTypes.Stage
	// AllowedStages returns all stages where the plugin is allowed to run.
	// This is used for validation to ensure the plugin is not configured to run on unsupported stages.
	AllowedStages() []pluginTypes.Stage
	Execute(
		ctx context.Context,
		cfg pluginTypes.PluginConfig,
		req *types.RequestContext,
		resp *types.ResponseContext,
		evtCtx *metrics.EventContext,
	) (*pluginTypes.PluginResponse, error)
	ValidateConfig(config pluginTypes.PluginConfig) error
	// RequiredPlugins returns the names of other plugins required by this one.
	RequiredPlugins() []string
}
