package request

import (
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type CreateRuleRequest struct {
	Path          string                 `json:"path" binding:"required"`
	Name          string                 `json:"name" binding:"required"`
	ServiceID     string                 `json:"service_id" binding:"required"`
	Methods       []string               `json:"methods"`
	Headers       map[string]string      `json:"headers"`
	StripPath     *bool                  `json:"strip_path"`
	PreserveHost  *bool                  `json:"preserve_host"`
	RetryAttempts *int                   `json:"retry_attempts"`
	PluginChain   []types.PluginConfig   `json:"plugin_chain"`
	TrustLens     *types.TrustLensConfig `json:"trustlens,omitempty"`
}

