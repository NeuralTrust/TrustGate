package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

type CreateConsumerRequest struct {
	Name       string            `json:"name"`
	Type       string            `json:"type,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Active     *bool             `json:"active,omitempty"`
	BackendIDs []string          `json:"backend_ids"`
	PolicyIDs  []string          `json:"policy_ids,omitempty"`
	AuthIDs    []string          `json:"auth_ids,omitempty"`
}

func (r CreateConsumerRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	if len(r.BackendIDs) == 0 {
		return fmt.Errorf("at least one backend_id is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r CreateConsumerRequest) ToType() domain.Type {
	return domain.Type(r.Type)
}

func (r CreateConsumerRequest) ToBackendIDs() ([]uuid.UUID, error) {
	return parseUUIDList(r.BackendIDs, "backend_ids")
}

func (r CreateConsumerRequest) ToPolicyIDs() ([]uuid.UUID, error) {
	return parseUUIDList(r.PolicyIDs, "policy_ids")
}

func (r CreateConsumerRequest) ToAuthIDs() ([]uuid.UUID, error) {
	return parseUUIDList(r.AuthIDs, "auth_ids")
}

func parseUUIDList(raw []string, field string) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0, len(raw))
	for i, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: invalid uuid %q: %w", field, i, s, commonerrors.ErrValidation)
		}
		out = append(out, id)
	}
	return out, nil
}
