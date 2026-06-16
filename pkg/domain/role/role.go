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

package role

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

// MCPPolicies mirrors the inline consumer MCP policy ({toolkit, fail_mode})
// so the wire format is identical whether the policy lives on the consumer
// (routing_mode=inline) or on a role (routing_mode=role_based).
type MCPPolicies = consumerdomain.MCPPolicy

type Role struct {
	ID            ids.RoleID       `json:"id"`
	GatewayID     ids.GatewayID    `json:"gateway_id"`
	Name          string           `json:"name"`
	ModelPolicies ModelPolicies    `json:"model_policies,omitempty"`
	MCPPolicies   *MCPPolicies     `json:"mcp_policies,omitempty"`
	IDPMapping    json.RawMessage  `json:"idp_mapping,omitempty"`
	RegistryIDs   []ids.RegistryID `json:"registry_ids,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type CreateParams struct {
	GatewayID     ids.GatewayID
	Name          string
	ModelPolicies ModelPolicies
	MCPPolicies   *MCPPolicies
	IDPMapping    json.RawMessage
	RegistryIDs   []ids.RegistryID
}

func New(params CreateParams) (*Role, error) {
	id, err := ids.NewV7[ids.RoleKind]()
	if err != nil {
		return nil, fmt.Errorf("role: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	r := &Role{
		ID:            id,
		GatewayID:     params.GatewayID,
		Name:          params.Name,
		ModelPolicies: params.ModelPolicies,
		MCPPolicies:   params.MCPPolicies,
		IDPMapping:    params.IDPMapping,
		RegistryIDs:   params.RegistryIDs,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func Rehydrate(
	id ids.RoleID,
	gatewayID ids.GatewayID,
	name string,
	modelPolicies ModelPolicies,
	mcpPolicies *MCPPolicies,
	idpMapping json.RawMessage,
	registryIDs []ids.RegistryID,
	createdAt, updatedAt time.Time,
) *Role {
	return &Role{
		ID:            id,
		GatewayID:     gatewayID,
		Name:          name,
		ModelPolicies: modelPolicies,
		MCPPolicies:   mcpPolicies,
		IDPMapping:    idpMapping,
		RegistryIDs:   registryIDs,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

func (r *Role) Validate() error {
	if r.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidName)
	}
	if r.MCPPolicies != nil {
		if err := r.MCPPolicies.Validate(r.BoundRegistrySet()); err != nil {
			return err
		}
	}
	if !validRawJSON(r.IDPMapping) {
		return fmt.Errorf("%w: idp_mapping", ErrInvalidJSON)
	}
	if err := ValidateIDPMapping(r.IDPMapping); err != nil {
		return err
	}
	return nil
}

func (r *Role) BoundRegistrySet() map[ids.RegistryID]struct{} {
	known := make(map[ids.RegistryID]struct{}, len(r.RegistryIDs))
	for _, id := range r.RegistryIDs {
		known[id] = struct{}{}
	}
	return known
}

func validRawJSON(raw json.RawMessage) bool {
	return len(raw) == 0 || json.Valid(raw)
}
