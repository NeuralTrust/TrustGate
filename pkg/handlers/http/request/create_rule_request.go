package request

import (
	"fmt"

	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type CreateRuleRequest struct {
	Path          types.FlexiblePath         `json:"path" binding:"required"`
	Name          string                     `json:"name" binding:"required"`
	ServiceID     string                     `json:"service_id" binding:"required"`
	Type          *string                    `json:"type,omitempty"`
	Methods       []string                   `json:"methods"`
	Headers       map[string]string          `json:"headers"`
	StripPath     *bool                      `json:"strip_path"`
	PreserveHost  *bool                      `json:"preserve_host"`
	RetryAttempts *int                       `json:"retry_attempts"`
	PluginChain   []pluginTypes.PluginConfig `json:"plugin_chain"`
	TrustLens     *types.TrustLensConfigDTO  `json:"trustlens,omitempty"`
	SessionConfig *types.SessionConfigDTO    `json:"session_config,omitempty"`
}

func (r *CreateRuleRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Path.Primary == "" {
		return fmt.Errorf("path is required")
	}
	if r.Path.IsMultiPath() {
		for i, p := range r.Path.All {
			if p == "" {
				return fmt.Errorf("paths[%d] must not be empty", i)
			}
		}
	}
	allPaths := []string{r.Path.Primary}
	if r.Path.IsMultiPath() {
		allPaths = r.Path.All
	}
	for _, p := range allPaths {
		if err := validateWildcardPath(p); err != nil {
			return err
		}
	}
	if len(r.Methods) == 0 {
		return fmt.Errorf("at least one method is required")
	}
	if r.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}
	if err := validateHTTPMethods(r.Methods); err != nil {
		return err
	}
	if r.Type != nil {
		if err := validateRuleType(*r.Type); err != nil {
			return err
		}
	}
	if r.TrustLens != nil {
		if err := validateTrustLens(r.TrustLens); err != nil {
			return err
		}
	}
	return nil
}
