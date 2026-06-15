package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type UpdateRegistryRequest struct {
	Name            *string              `json:"name,omitempty"`
	Provider        *string              `json:"provider,omitempty"`
	ProviderOptions *map[string]any      `json:"provider_options,omitempty"`
	Description     *string              `json:"description,omitempty"`
	Auth            *TargetAuthRequest   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksRequest `json:"health_checks,omitempty"`
	MCPTarget       *MCPTargetRequest    `json:"mcp_target,omitempty"`
}

func (r UpdateRegistryRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	if r.Provider != nil && strings.TrimSpace(*r.Provider) == "" {
		return fmt.Errorf("provider is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateRegistryRequest) ToAuth() *domain.TargetAuth {
	return r.Auth.ToDomain()
}

func (r UpdateRegistryRequest) ToHealthChecks() *domain.HealthChecks {
	return r.HealthChecks.ToDomain()
}

func (r UpdateRegistryRequest) ToMCPTarget() *domain.MCPTarget {
	return r.MCPTarget.ToDomain()
}
