package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

const maxPolicyDescriptionLen = 1000

type CreatePolicyRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Slug        string         `json:"slug"`
	Enabled     bool           `json:"enabled"`
	Priority    int            `json:"priority,omitempty"`
	Parallel    *bool          `json:"parallel,omitempty"`
	Settings    map[string]any `json:"settings,omitempty"`
	Stages      []string       `json:"stages,omitempty"`
}

func (r CreatePolicyRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if len(r.Description) > maxPolicyDescriptionLen {
		return fmt.Errorf("description too long (max %d): %w", maxPolicyDescriptionLen, commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Slug) == "" {
		return fmt.Errorf("slug is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r CreatePolicyRequest) ToStages() []domain.Stage {
	return toStages(r.Stages)
}

func (r CreatePolicyRequest) ParallelOrDefault() bool {
	if r.Parallel == nil {
		return true
	}
	return *r.Parallel
}

func toStages(raw []string) []domain.Stage {
	if len(raw) == 0 {
		return nil
	}
	out := make([]domain.Stage, 0, len(raw))
	for _, s := range raw {
		out = append(out, domain.Stage(s))
	}
	return out
}
