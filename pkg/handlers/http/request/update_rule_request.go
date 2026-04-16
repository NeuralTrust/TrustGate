package request

import (
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type UpdateRuleRequest struct {
	Path          *types.FlexiblePath        `json:"path,omitempty"`
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
	SessionConfig *types.SessionConfigDTO    `json:"session_config,omitempty"`
}

func (r *UpdateRuleRequest) Validate() error {
	if err := validateHTTPMethods(r.Methods); err != nil {
		return err
	}
	if r.Type != nil {
		if err := validateRuleType(*r.Type); err != nil {
			return err
		}
	}
	if r.Path != nil {
		allPaths := []string{r.Path.Primary}
		if r.Path.IsMultiPath() {
			allPaths = r.Path.All
		}
		for _, p := range allPaths {
			if err := validateWildcardPath(p); err != nil {
				return err
			}
		}
	}
	if r.TrustLens != nil {
		if err := validateTrustLens(r.TrustLens); err != nil {
			return err
		}
	}
	return nil
}
