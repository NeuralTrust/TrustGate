package request

import (
	"encoding/json"
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
)

type CreateRoleRequest struct {
	Name          string               `json:"name"`
	ModelPolicies []ModelPolicyRequest `json:"model_policies,omitempty"`
	McpPolicies   json.RawMessage      `json:"mcp_policies,omitempty"`
	IDPMapping    json.RawMessage      `json:"idp_mapping,omitempty"`
}

type UpdateRoleRequest struct {
	Name          *string               `json:"name,omitempty"`
	ModelPolicies *[]ModelPolicyRequest `json:"model_policies,omitempty"`
	McpPolicies   *json.RawMessage      `json:"mcp_policies,omitempty"`
	IDPMapping    *json.RawMessage      `json:"idp_mapping,omitempty"`
}

type ListRoleRequest struct {
	Name string
	Page int
	Size int
}

type ModelPolicyRequest struct {
	RegistryID string   `json:"registry_id"`
	Allowed    []string `json:"allowed,omitempty"`
	Default    string   `json:"default,omitempty"`
}

func (r CreateRoleRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.ModelPolicies) > 0 {
		return fmt.Errorf("model_policies cannot be set on create; bind registries first and update the role: %w", commonerrors.ErrValidation)
	}
	if err := domain.ValidateIDPMapping(r.IDPMapping); err != nil {
		return fmt.Errorf("%v: %w", err, commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateRoleRequest) Validate() error {
	if r.Name != nil && strings.TrimSpace(*r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if r.IDPMapping != nil {
		if err := domain.ValidateIDPMapping(*r.IDPMapping); err != nil {
			return fmt.Errorf("%v: %w", err, commonerrors.ErrValidation)
		}
	}
	return nil
}

func (r UpdateRoleRequest) ToModelPolicies() (*domain.ModelPolicies, error) {
	if r.ModelPolicies == nil {
		return nil, nil
	}
	modelPolicies, err := parseModelPolicies(*r.ModelPolicies)
	if err != nil {
		return nil, err
	}
	return &modelPolicies, nil
}

func parseModelPolicies(raw []ModelPolicyRequest) (domain.ModelPolicies, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(domain.ModelPolicies, len(raw))
	for i, policy := range raw {
		id, err := ids.Parse[ids.RegistryKind](policy.RegistryID)
		if err != nil {
			return nil, fmt.Errorf("model_policies[%d]: invalid registry_id %q: %w", i, policy.RegistryID, commonerrors.ErrValidation)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("model_policies[%d]: duplicate registry_id %q: %w", i, policy.RegistryID, commonerrors.ErrValidation)
		}
		out[id] = domain.ModelPolicy{Allowed: policy.Allowed, Default: policy.Default}
	}
	return out, nil
}
