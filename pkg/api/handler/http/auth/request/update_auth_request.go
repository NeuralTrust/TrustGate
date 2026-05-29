package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

type UpdateAuthRequest struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Enabled *bool         `json:"enabled,omitempty"`
	Config  ConfigRequest `json:"config"`
}

func (r UpdateAuthRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Type) == "" {
		return fmt.Errorf("type is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateAuthRequest) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}
