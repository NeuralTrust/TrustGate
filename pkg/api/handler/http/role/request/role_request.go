// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package request

import (
	"encoding/json"
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

type CreateRoleRequest struct {
	Name          string               `json:"name"`
	ModelPolicies []ModelPolicyRequest `json:"model_policies,omitempty"`
	McpPolicies   *MCPPoliciesRequest  `json:"mcp_policies,omitempty"`
	OIDCMapping    json.RawMessage      `json:"oidc_mapping,omitempty"`
}

type UpdateRoleRequest struct {
	Name          *string               `json:"name,omitempty"`
	ModelPolicies *[]ModelPolicyRequest `json:"model_policies,omitempty"`
	McpPolicies   *MCPPoliciesRequest   `json:"mcp_policies,omitempty"`
	OIDCMapping    *json.RawMessage      `json:"oidc_mapping,omitempty"`
}

type MCPPoliciesRequest struct {
	Toolkit  []ToolkitEntryRequest `json:"toolkit,omitempty"`
	FailMode string                `json:"fail_mode,omitempty"`
}

type ToolkitEntryRequest struct {
	RegistryID string `json:"registry_id"`
	Tool       string `json:"tool,omitempty"`
	Prompt     string `json:"prompt,omitempty"`
	Resource   string `json:"resource,omitempty"`
	ExposeAs   string `json:"expose_as,omitempty"`
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
	if r.McpPolicies != nil {
		return fmt.Errorf("mcp_policies cannot be set on create; bind registries first and update the role: %w", commonerrors.ErrValidation)
	}
	if err := domain.ValidateOIDCMapping(r.OIDCMapping); err != nil {
		return fmt.Errorf("%v: %w", err, commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateRoleRequest) Validate() error {
	if r.Name != nil && strings.TrimSpace(*r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if r.OIDCMapping != nil {
		if err := domain.ValidateOIDCMapping(*r.OIDCMapping); err != nil {
			return fmt.Errorf("%v: %w", err, commonerrors.ErrValidation)
		}
	}
	return nil
}

func (r UpdateRoleRequest) ToMCPPolicies() (*domain.MCPPolicies, bool, error) {
	if r.McpPolicies == nil {
		return nil, false, nil
	}
	policies, err := parseMCPPolicies(*r.McpPolicies)
	if err != nil {
		return nil, false, err
	}
	return policies, true, nil
}

func parseMCPPolicies(raw MCPPoliciesRequest) (*domain.MCPPolicies, error) {
	toolkit := make(consumerdomain.Toolkit, 0, len(raw.Toolkit))
	for i, e := range raw.Toolkit {
		id, err := ids.Parse[ids.RegistryKind](e.RegistryID)
		if err != nil {
			return nil, fmt.Errorf("mcp_policies.toolkit[%d]: invalid registry_id %q: %w", i, e.RegistryID, commonerrors.ErrValidation)
		}
		toolkit = append(toolkit, consumerdomain.ToolkitEntry{
			RegistryID: id,
			Tool:       e.Tool,
			Prompt:     e.Prompt,
			Resource:   e.Resource,
			ExposeAs:   e.ExposeAs,
		})
	}
	return &domain.MCPPolicies{
		Toolkit:  toolkit,
		FailMode: consumerdomain.FailMode(strings.TrimSpace(raw.FailMode)),
	}, nil
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
