package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type UpdatePolicyRequest struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Slug        *string         `json:"slug,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty"`
	Priority    *int            `json:"priority,omitempty"`
	Parallel    *bool           `json:"parallel,omitempty"`
	Settings    *map[string]any `json:"settings,omitempty"`
	Stages      *[]string       `json:"stages,omitempty"`
}

func (r UpdatePolicyRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	if r.Description != nil && len(*r.Description) > maxPolicyDescriptionLen {
		return fmt.Errorf("description too long (max %d): %w", maxPolicyDescriptionLen, commonerrors.ErrValidation)
	}
	if r.Slug != nil && strings.TrimSpace(*r.Slug) == "" {
		return fmt.Errorf("slug is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdatePolicyRequest) ToStages() *[]domain.Stage {
	if r.Stages == nil {
		return nil
	}
	stages := toStages(*r.Stages)
	return &stages
}
