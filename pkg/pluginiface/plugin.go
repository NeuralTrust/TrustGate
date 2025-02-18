package pluginiface

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Plugin interface {
	Name() string
	// Stages returns the fixed stages where the plugin must run.
	// If empty, the plugin will run on the stage specified in the config.
	Stages() []types.Stage
	// AllowedStages returns all stages where the plugin is allowed to run.
	// This is used for validation to ensure the plugin is not configured to run on unsupported stages.
	AllowedStages() []types.Stage
	Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error)
	ValidateConfig(config types.PluginConfig) error
}
