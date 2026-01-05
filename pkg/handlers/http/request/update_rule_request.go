package request

import (
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type UpdateRuleRequest struct {
	Path          string                     `json:"path"`
	Name          string                     `json:"name"`
	ServiceID     string                     `json:"service_id"`
	Type          *string                    `json:"type,omitempty"`
	Methods       []string                   `json:"methods"`
	Headers       map[string]string          `json:"headers"`
	StripPath     *bool                      `json:"strip_path"`
	PreserveHost  *bool                      `json:"preserve_host"`
	RetryAttempts *int                       `json:"retry_attempts"`
	Active        *bool                      `json:"active"`
	PluginChain   []pluginTypes.PluginConfig `json:"plugin_chain"`
	TrustLens     *types.TrustLensConfigDTO  `json:"trustlens,omitempty"`
}
