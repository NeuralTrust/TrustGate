package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type TestConnectionRequest struct {
	RegistryID      string             `json:"registry_id,omitempty"`
	Provider        string             `json:"provider,omitempty"`
	ProviderOptions map[string]any     `json:"provider_options,omitempty"`
	Auth            *TargetAuthRequest `json:"auth,omitempty"`
}

func (r TestConnectionRequest) IsByID() bool {
	return strings.TrimSpace(r.RegistryID) != ""
}

func (r TestConnectionRequest) Validate() error {
	if r.IsByID() {
		if r.Provider != "" || r.Auth != nil {
			return fmt.Errorf("registry_id cannot be combined with provider/auth: %w", commonerrors.ErrValidation)
		}
		return nil
	}
	if strings.TrimSpace(r.Provider) == "" {
		return fmt.Errorf("provider is required when registry_id is not set: %w", commonerrors.ErrValidation)
	}
	if r.Auth == nil {
		return fmt.Errorf("auth is required when registry_id is not set: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r TestConnectionRequest) ToAuth() *domain.TargetAuth {
	return r.Auth.ToDomain()
}
