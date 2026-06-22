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

package response

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

type RoleResponse struct {
	ID            ids.RoleID            `json:"id"`
	GatewayID     ids.GatewayID         `json:"gateway_id"`
	Name          string                `json:"name"`
	ModelPolicies []ModelPolicyResponse `json:"model_policies,omitempty"`
	McpPolicies   *domain.MCPPolicies   `json:"mcp_policies,omitempty"`
	OIDCMapping    json.RawMessage       `json:"oidc_mapping,omitempty"`
	RegistryIDs   []ids.RegistryID      `json:"registry_ids"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

type ModelPolicyResponse struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Allowed    []string       `json:"allowed,omitempty"`
	Default    string         `json:"default,omitempty"`
}

type ListRoleResponse struct {
	Items []RoleResponse `json:"items"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
	Total int            `json:"total"`
}

func FromRole(role *domain.Role) RoleResponse {
	if role == nil {
		return RoleResponse{}
	}
	registryIDs := role.RegistryIDs
	if registryIDs == nil {
		registryIDs = []ids.RegistryID{}
	}
	return RoleResponse{
		ID:            role.ID,
		GatewayID:     role.GatewayID,
		Name:          role.Name,
		ModelPolicies: fromModelPolicies(role.ModelPolicies),
		McpPolicies:   role.MCPPolicies,
		OIDCMapping:    role.OIDCMapping,
		RegistryIDs:   registryIDs,
		CreatedAt:     role.CreatedAt,
		UpdatedAt:     role.UpdatedAt,
	}
}

func fromModelPolicies(policies domain.ModelPolicies) []ModelPolicyResponse {
	if len(policies) == 0 {
		return nil
	}
	out := make([]ModelPolicyResponse, 0, len(policies))
	for registryID, policy := range policies {
		out = append(out, ModelPolicyResponse{
			RegistryID: registryID,
			Allowed:    policy.Allowed,
			Default:    policy.Default,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RegistryID.String() < out[j].RegistryID.String()
	})
	return out
}
