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

package registry

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type Registry struct {
	ID          ids.RegistryID `json:"id"`
	GatewayID   ids.GatewayID  `json:"gateway_id"`
	Name        string         `json:"name"`
	Type        Type           `json:"type"`
	Enabled     bool           `json:"enabled"`
	Description string         `json:"description,omitempty"`
	// ToolPolicy only applies to MCP registries; the zero value reads as auto.
	ToolPolicy ToolPolicy `json:"tool_policy,omitempty"`
	// PinnedTools is the decided tool set of a pinned registry as the config
	// snapshot carries it to DB-less data planes, which have no registry_tools
	// table to read. It is filled by the snapshot compiler only: the registry
	// repository never loads or stores it. An empty set on a pinned registry
	// means nothing is approved, so nothing is exposed. The slice is omitted
	// when empty, which keeps the snapshot bytes of auto registries unchanged.
	PinnedTools []ToolDecision `json:"pinned_tools,omitempty"`
	LLMTarget   *LLMTarget     `json:"llm_target,omitempty"`
	MCPTarget   *MCPTarget     `json:"mcp_target,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`

	// InstanceOf names the shelf registry a per-principal Store clone derives
	// from. It is a request-scoped view built by the Store scoper: never
	// persisted and never carried by the config snapshot.
	InstanceOf ids.RegistryID `json:"-"`
}

// ScopeKey returns the registry id an MCP policy scope has to name to reach
// this registry: the shelf id for a Store instance clone, otherwise its own id.
func (b *Registry) ScopeKey() ids.RegistryID {
	if !b.InstanceOf.IsNil() {
		return b.InstanceOf
	}
	return b.ID
}

func NewLLMRegistry(
	gatewayID ids.GatewayID,
	name, description string,
	target *LLMTarget,
) (*Registry, error) {
	id, err := ids.NewV7[ids.RegistryKind]()
	if err != nil {
		return nil, fmt.Errorf("registry: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	b := &Registry{
		ID:          id,
		GatewayID:   gatewayID,
		Name:        name,
		Type:        TypeLLM,
		Enabled:     true,
		Description: description,
		ToolPolicy:  ToolPolicyAuto,
		LLMTarget:   target,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func NewMCPRegistry(
	gatewayID ids.GatewayID,
	name, description string,
	target *MCPTarget,
) (*Registry, error) {
	id, err := ids.NewV7[ids.RegistryKind]()
	if err != nil {
		return nil, fmt.Errorf("registry: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	b := &Registry{
		ID:          id,
		GatewayID:   gatewayID,
		Name:        name,
		Type:        TypeMCP,
		Enabled:     true,
		Description: description,
		ToolPolicy:  ToolPolicyAuto,
		MCPTarget:   target,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Registry) IsMCP() bool {
	return b.Type == TypeMCP
}

func (b *Registry) Provider() string {
	if b.LLMTarget == nil {
		return ""
	}
	return b.LLMTarget.Provider
}

func (b *Registry) ProviderOptions() map[string]any {
	if b.LLMTarget == nil {
		return nil
	}
	return b.LLMTarget.ProviderOptions
}

func (b *Registry) Auth() *TargetAuth {
	if b.LLMTarget == nil {
		return nil
	}
	return b.LLMTarget.Auth
}

func (b *Registry) HealthChecks() *HealthChecks {
	if b.LLMTarget == nil {
		return nil
	}
	return b.LLMTarget.HealthChecks
}

func (b *Registry) Pricing() *Pricing {
	if b.LLMTarget == nil {
		return nil
	}
	return b.LLMTarget.Pricing
}

type RehydrateParams struct {
	ID          ids.RegistryID
	GatewayID   ids.GatewayID
	Name        string
	Type        Type
	Enabled     bool
	Description string
	ToolPolicy  ToolPolicy
	LLMTarget   *LLMTarget
	MCPTarget   *MCPTarget
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func Rehydrate(params RehydrateParams) *Registry {
	regType := params.Type
	if regType == "" {
		regType = TypeLLM
	}
	return &Registry{
		ID:          params.ID,
		GatewayID:   params.GatewayID,
		Name:        params.Name,
		Type:        regType,
		Enabled:     params.Enabled,
		Description: params.Description,
		ToolPolicy:  params.ToolPolicy.Normalize(),
		LLMTarget:   params.LLMTarget,
		MCPTarget:   params.MCPTarget,
		CreatedAt:   params.CreatedAt,
		UpdatedAt:   params.UpdatedAt,
	}
}

func (b *Registry) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidRegistry)
	}
	if b.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if b.Type == "" {
		b.Type = TypeLLM
	}
	b.ToolPolicy = b.ToolPolicy.Normalize()
	if err := b.ToolPolicy.Validate(); err != nil {
		return err
	}
	if b.ToolPolicy.IsPinned() && b.Type != TypeMCP {
		return fmt.Errorf("%w: pinned is only valid for MCP registries", ErrInvalidToolPolicy)
	}
	switch b.Type {
	case TypeLLM:
		return b.validateLLM()
	case TypeMCP:
		return b.validateMCP()
	default:
		return fmt.Errorf("%w: unsupported type %q", ErrInvalidRegistry, b.Type)
	}
}

func (b *Registry) validateLLM() error {
	if b.MCPTarget != nil {
		return fmt.Errorf("%w: mcp_target is only valid for MCP registries", ErrInvalidRegistry)
	}
	return b.LLMTarget.Validate()
}

func (b *Registry) validateMCP() error {
	if b.LLMTarget != nil {
		return fmt.Errorf("%w: llm_target is only valid for LLM registries", ErrInvalidRegistry)
	}
	if b.MCPTarget == nil {
		return fmt.Errorf("%w: mcp_target is required for MCP registries", ErrInvalidMCPTarget)
	}
	b.MCPTarget.Normalize()
	return b.MCPTarget.Validate()
}
