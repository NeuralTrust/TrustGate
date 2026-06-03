package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type UpdateConsumerRequest struct {
	Name            string                  `json:"name"`
	Type            string                  `json:"type,omitempty"`
	Path            string                  `json:"path"`
	Algorithm       string                  `json:"algorithm,omitempty"`
	EmbeddingConfig *EmbeddingConfigRequest `json:"embedding_config,omitempty"`
	Headers         map[string]string       `json:"headers,omitempty"`
	Active          *bool                   `json:"active,omitempty"`
	RegistryIDs     []string                `json:"registry_ids"`
	PolicyIDs       []string                `json:"policy_ids,omitempty"`
	AuthIDs         []string                `json:"auth_ids,omitempty"`
	Fallback        *FallbackRequest        `json:"fallback,omitempty"`
	ModelPolicies   []ModelPolicyRequest    `json:"model_policies,omitempty"`
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
	if len(r.RegistryIDs) == 0 {
		return fmt.Errorf("at least one registry_id is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateConsumerRequest) ToType() domain.Type {
	return domain.Type(r.Type)
}

func (r UpdateConsumerRequest) ToEmbeddingConfig() *registrydomain.EmbeddingConfig {
	return r.EmbeddingConfig.ToDomain()
}

func (r UpdateConsumerRequest) ToRegistryIDs() ([]ids.RegistryID, error) {
	return parseUUIDList[ids.RegistryKind](r.RegistryIDs, "registry_ids")
}

func (r UpdateConsumerRequest) ToPolicyIDs() ([]ids.PolicyID, error) {
	return parseUUIDList[ids.PolicyKind](r.PolicyIDs, "policy_ids")
}

func (r UpdateConsumerRequest) ToAuthIDs() ([]ids.AuthID, error) {
	return parseUUIDList[ids.AuthKind](r.AuthIDs, "auth_ids")
}

func (r UpdateConsumerRequest) ToFallback() (*domain.Fallback, error) {
	return r.Fallback.ToFallback()
}

func (r UpdateConsumerRequest) ToModelPolicies() (domain.ModelPolicies, error) {
	return parseModelPolicies(r.ModelPolicies)
}
