package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
)

type UpdateBackendRequest struct {
	Name            string                  `json:"name"`
	Algorithm       string                  `json:"algorithm,omitempty"`
	Targets         []TargetRequest         `json:"targets"`
	EmbeddingConfig *EmbeddingConfigRequest `json:"embedding_config,omitempty"`
	HealthChecks    *HealthChecksRequest    `json:"health_checks,omitempty"`
}

func (r UpdateBackendRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("at least one target is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateBackendRequest) ToTargets() domain.Targets {
	out := make(domain.Targets, 0, len(r.Targets))
	for _, tr := range r.Targets {
		out = append(out, tr.ToDomain())
	}
	return out
}

func (r UpdateBackendRequest) ToEmbeddingConfig() *domain.EmbeddingConfig {
	if r.EmbeddingConfig == nil {
		return nil
	}
	return r.EmbeddingConfig.ToDomain()
}

func (r UpdateBackendRequest) ToHealthChecks() *domain.HealthChecks {
	return r.HealthChecks.ToDomain()
}
