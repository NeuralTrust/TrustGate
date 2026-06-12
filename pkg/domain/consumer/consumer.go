package consumer

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type Type string

const (
	TypeLLM Type = "LLM"
	TypeMCP Type = "MCP"
	TypeA2A Type = "A2A"
)

func Types() []Type {
	return []Type{TypeLLM, TypeMCP, TypeA2A}
}

func IsValidType(t Type) bool {
	switch t {
	case TypeLLM, TypeMCP, TypeA2A:
		return true
	}
	return false
}

type Consumer struct {
	ID          ids.ConsumerID      `json:"id"`
	GatewayID   ids.GatewayID       `json:"gateway_id"`
	Name        string              `json:"name"`
	Type        Type                `json:"type"`
	Path        string              `json:"path"`
	Headers     map[string]string   `json:"headers,omitempty"`
	Active      bool                `json:"active"`
	RegistryIDs registry.Registries `json:"registry_ids"`
	AuthIDs     []ids.AuthID        `json:"auth_ids"`
	LLM         *LLMPolicy          `json:"llm,omitempty"`
	MCP         *MCPPolicy          `json:"mcp,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

func (c *Consumer) Algorithm() string {
	if c.LLM == nil {
		return ""
	}
	return c.LLM.Algorithm
}

func (c *Consumer) EmbeddingConfig() *registry.EmbeddingConfig {
	if c.LLM == nil {
		return nil
	}
	return c.LLM.EmbeddingConfig
}

func (c *Consumer) ModelPolicies() ModelPolicies {
	if c.LLM == nil {
		return nil
	}
	return c.LLM.ModelPolicies
}

func (c *Consumer) Fallback() *Fallback {
	if c.LLM == nil {
		return nil
	}
	return c.LLM.Fallback
}

func (c *Consumer) Toolkit() Toolkit {
	if c.MCP == nil {
		return nil
	}
	return c.MCP.Toolkit
}

func (c *Consumer) FailMode() FailMode {
	if c.MCP == nil {
		return ""
	}
	return c.MCP.FailMode
}

type CreateParams struct {
	GatewayID   ids.GatewayID
	Name        string
	Type        Type
	Path        string
	Headers     map[string]string
	Active      *bool
	RegistryIDs []ids.RegistryID
	AuthIDs     []ids.AuthID
	LLM         *LLMPolicy
	MCP         *MCPPolicy
}

func New(params CreateParams) (*Consumer, error) {
	id, err := ids.NewV7[ids.ConsumerKind]()
	if err != nil {
		return nil, fmt.Errorf("consumer: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	active := true
	if params.Active != nil {
		active = *params.Active
	}
	c := &Consumer{
		ID:          id,
		GatewayID:   params.GatewayID,
		Name:        params.Name,
		Type:        params.Type,
		Path:        params.Path,
		Headers:     params.Headers,
		Active:      active,
		RegistryIDs: params.RegistryIDs,
		AuthIDs:     params.AuthIDs,
		LLM:         params.LLM,
		MCP:         params.MCP,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

type RehydrateParams struct {
	ID          ids.ConsumerID
	GatewayID   ids.GatewayID
	Name        string
	Type        Type
	Path        string
	Headers     map[string]string
	Active      bool
	RegistryIDs []ids.RegistryID
	AuthIDs     []ids.AuthID
	LLM         *LLMPolicy
	MCP         *MCPPolicy
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func Rehydrate(params RehydrateParams) *Consumer {
	return &Consumer{
		ID:          params.ID,
		GatewayID:   params.GatewayID,
		Name:        params.Name,
		Type:        params.Type,
		Path:        params.Path,
		Headers:     params.Headers,
		Active:      params.Active,
		RegistryIDs: params.RegistryIDs,
		AuthIDs:     params.AuthIDs,
		LLM:         params.LLM,
		MCP:         params.MCP,
		CreatedAt:   params.CreatedAt,
		UpdatedAt:   params.UpdatedAt,
	}
}

func (c *Consumer) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidName)
	}
	if c.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if c.Type == "" {
		c.Type = TypeLLM
	}
	if !IsValidType(c.Type) {
		return fmt.Errorf("%w: %q", ErrInvalidType, c.Type)
	}
	if strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("%w: path is required", ErrInvalidPath)
	}
	if err := c.RegistryIDs.Validate(); err != nil {
		return err
	}
	if err := validateUniqueIDs(c.AuthIDs, ErrInvalidAuthID, "auth"); err != nil {
		return err
	}
	switch c.Type {
	case TypeLLM:
		if c.MCP != nil {
			return fmt.Errorf("%w: mcp policy is only valid for MCP consumers", ErrInvalidType)
		}
		if c.LLM == nil {
			c.LLM = &LLMPolicy{}
		}
		return c.LLM.Validate(c.knownRegistryIDs())
	case TypeMCP:
		if c.LLM != nil {
			return fmt.Errorf("%w: llm policy is only valid for LLM consumers", ErrInvalidType)
		}
		if c.MCP == nil {
			c.MCP = &MCPPolicy{}
		}
		return c.MCP.Validate(c.knownRegistryIDs())
	case TypeA2A:
		if c.LLM != nil {
			return fmt.Errorf("%w: llm policy is only valid for LLM consumers", ErrInvalidType)
		}
		if c.MCP != nil {
			return fmt.Errorf("%w: mcp policy is only valid for MCP consumers", ErrInvalidType)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidType, c.Type)
	}
}

func (c *Consumer) knownRegistryIDs() map[ids.RegistryID]struct{} {
	known := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		known[id] = struct{}{}
	}
	if fb := c.Fallback(); fb != nil {
		for _, id := range fb.Chain {
			known[id] = struct{}{}
		}
	}
	return known
}

type identifier interface {
	comparable
	fmt.Stringer
	IsNil() bool
}

func validateUniqueIDs[T identifier](list []T, invalidErr error, label string) error {
	seen := make(map[T]struct{}, len(list))
	for _, id := range list {
		if id.IsNil() {
			return fmt.Errorf("%w: nil uuid", invalidErr)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate %s %s", invalidErr, label, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
