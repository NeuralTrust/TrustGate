package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

type UpdateAuthRequest struct {
	Name    *string        `json:"name,omitempty"`
	Type    *string        `json:"type,omitempty"`
	Enabled *bool          `json:"enabled,omitempty"`
	Config  *ConfigRequest `json:"config,omitempty"`
}

func (r UpdateAuthRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	if r.Type != nil && strings.TrimSpace(*r.Type) == "" {
		return fmt.Errorf("type is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateAuthRequest) ToType() *domain.Type {
	if r.Type == nil {
		return nil
	}
	t := domain.Type(*r.Type)
	return &t
}

func (r UpdateAuthRequest) ToConfig() *domain.Config {
	if r.Config == nil {
		return nil
	}
	cfg := r.Config.ToDomain()
	return &cfg
}
