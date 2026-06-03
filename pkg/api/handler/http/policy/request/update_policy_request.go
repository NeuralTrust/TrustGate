package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type UpdatePolicyRequest struct {
	Name     string         `json:"name"`
	Slug     string         `json:"slug"`
	Enabled  bool           `json:"enabled"`
	Priority int            `json:"priority"`
	Parallel bool           `json:"parallel,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
	Stages   []string       `json:"stages,omitempty"`
}

func (r UpdatePolicyRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Slug) == "" {
		return fmt.Errorf("slug is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdatePolicyRequest) ToStages() []domain.Stage {
	return toStages(r.Stages)
}
