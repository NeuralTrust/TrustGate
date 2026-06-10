package role

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Role struct {
	ID            ids.RoleID       `json:"id"`
	GatewayID     ids.GatewayID    `json:"gateway_id"`
	Name          string           `json:"name"`
	ModelPolicies ModelPolicies    `json:"model_policies,omitempty"`
	McpPolicies   json.RawMessage  `json:"mcp_policies,omitempty"`
	IDPMapping    json.RawMessage  `json:"idp_mapping,omitempty"`
	RegistryIDs   []ids.RegistryID `json:"registry_ids,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type CreateParams struct {
	GatewayID     ids.GatewayID
	Name          string
	ModelPolicies ModelPolicies
	McpPolicies   json.RawMessage
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
		McpPolicies:   params.McpPolicies,
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
	mcpPolicies json.RawMessage,
	idpMapping json.RawMessage,
	registryIDs []ids.RegistryID,
	createdAt, updatedAt time.Time,
) *Role {
	return &Role{
		ID:            id,
		GatewayID:     gatewayID,
		Name:          name,
		ModelPolicies: modelPolicies,
		McpPolicies:   mcpPolicies,
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
	if !validRawJSON(r.McpPolicies) {
		return fmt.Errorf("%w: mcp_policies", ErrInvalidJSON)
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
