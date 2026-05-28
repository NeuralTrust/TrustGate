package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

type UpdateConsumerRequest struct {
	Name          string            `json:"name"`
	Type          string            `json:"type,omitempty"`
	Path          string            `json:"path"`
	Paths         []string          `json:"paths,omitempty"`
	Methods       []string          `json:"methods,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     bool              `json:"strip_path,omitempty"`
	PreserveHost  bool              `json:"preserve_host,omitempty"`
	Active        *bool             `json:"active,omitempty"`
	Public        bool              `json:"public,omitempty"`
	RetryAttempts int               `json:"retry_attempts,omitempty"`
	BackendIDs    []string          `json:"backend_ids"`
}

func (r UpdateConsumerRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("path is required: %w", commonerrors.ErrValidation)
	}
	if len(r.BackendIDs) == 0 {
		return fmt.Errorf("at least one backend_id is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateConsumerRequest) ToType() domain.Type {
	return domain.Type(r.Type)
}

func (r UpdateConsumerRequest) ToBackendIDs() ([]uuid.UUID, error) {
	return parseBackendIDs(r.BackendIDs)
}
