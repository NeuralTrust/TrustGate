package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
)

type UpdateBackendRequest struct {
	Name            string               `json:"name"`
	Provider        string               `json:"provider"`
	ProviderOptions map[string]any       `json:"provider_options,omitempty"`
	Description     string               `json:"description,omitempty"`
	Weight          int                  `json:"weight,omitempty"`
	Auth            *TargetAuthRequest   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksRequest `json:"health_checks,omitempty"`
}

func (r UpdateBackendRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Provider) == "" {
		return fmt.Errorf("provider is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateBackendRequest) ToAuth() *domain.TargetAuth {
	return r.Auth.ToDomain()
}

func (r UpdateBackendRequest) ToHealthChecks() *domain.HealthChecks {
	return r.HealthChecks.ToDomain()
}
