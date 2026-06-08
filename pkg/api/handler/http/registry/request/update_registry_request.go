package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type UpdateRegistryRequest struct {
	Name            string               `json:"name"`
	Provider        string               `json:"provider"`
	ProviderOptions map[string]any       `json:"provider_options,omitempty"`
	Description     string               `json:"description,omitempty"`
	Weight          int                  `json:"weight,omitempty"`
	Auth            *TargetAuthRequest   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksRequest `json:"health_checks,omitempty"`
}

func (r UpdateRegistryRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Provider) == "" {
		return fmt.Errorf("provider is required: %w", commonerrors.ErrValidation)
	}
	if r.Weight < 0 {
		return fmt.Errorf("weight cannot be negative: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateRegistryRequest) ToAuth() *domain.TargetAuth {
	return r.Auth.ToDomain()
}

func (r UpdateRegistryRequest) ToHealthChecks() *domain.HealthChecks {
	return r.HealthChecks.ToDomain()
}
