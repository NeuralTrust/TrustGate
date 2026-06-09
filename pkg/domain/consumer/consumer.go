package consumer

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
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
	ID              ids.ConsumerID            `json:"id"`
	GatewayID       ids.GatewayID             `json:"gateway_id"`
	Name            string                    `json:"name"`
	Type            Type                      `json:"type"`
	Path            string                    `json:"path"`
	Algorithm       string                    `json:"algorithm"`
	EmbeddingConfig *registry.EmbeddingConfig `json:"embedding_config,omitempty"`
	Headers         map[string]string         `json:"headers,omitempty"`
	Active          bool                      `json:"active"`
	RegistryIDs     registry.Registries       `json:"registry_ids"`
	AuthIDs         []ids.AuthID              `json:"auth_ids"`
	Fallback        *Fallback                 `json:"fallback,omitempty"`
	ModelPolicies   ModelPolicies             `json:"model_policies,omitempty"`
	Toolkit         Toolkit                   `json:"toolkit,omitempty"`
	FailMode        FailMode                  `json:"fail_mode,omitempty"`
	CreatedAt       time.Time                 `json:"created_at"`
	UpdatedAt       time.Time                 `json:"updated_at"`
}

type CreateParams struct {
	GatewayID       ids.GatewayID
	Name            string
	Type            Type
	Path            string
	Algorithm       string
	EmbeddingConfig *registry.EmbeddingConfig
	Headers         map[string]string
	Active          *bool
	RegistryIDs     []ids.RegistryID
	AuthIDs         []ids.AuthID
	Fallback        *Fallback
	ModelPolicies   ModelPolicies
	Toolkit         Toolkit
	FailMode        FailMode
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
		ID:              id,
		GatewayID:       params.GatewayID,
		Name:            params.Name,
		Type:            params.Type,
		Path:            params.Path,
		Algorithm:       params.Algorithm,
		EmbeddingConfig: params.EmbeddingConfig,
		Headers:         params.Headers,
		Active:          active,
		RegistryIDs:     params.RegistryIDs,
		AuthIDs:         params.AuthIDs,
		Fallback:        params.Fallback,
		ModelPolicies:   params.ModelPolicies,
		Toolkit:         params.Toolkit,
		FailMode:        params.FailMode,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func Rehydrate(
	id ids.ConsumerID,
	gatewayID ids.GatewayID,
	name string,
	consumerType Type,
	path, algo string,
	embeddingConfig *registry.EmbeddingConfig,
	headers map[string]string,
	active bool,
	registryIDs []ids.RegistryID,
	authIDs []ids.AuthID,
	fallback *Fallback,
	modelPolicies ModelPolicies,
	createdAt, updatedAt time.Time,
) *Consumer {
	return &Consumer{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            name,
		Type:            consumerType,
		Path:            path,
		Algorithm:       algo,
		EmbeddingConfig: embeddingConfig,
		Headers:         headers,
		Active:          active,
		RegistryIDs:     registryIDs,
		AuthIDs:         authIDs,
		Fallback:        fallback,
		ModelPolicies:   modelPolicies,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
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
	if c.Algorithm == "" {
		c.Algorithm = algorithm.RoundRobin
	}
	if !algorithm.IsValid(c.Algorithm) {
		return fmt.Errorf("%w: %q", ErrInvalidAlgorithm, c.Algorithm)
	}
	if c.Algorithm == algorithm.Semantic {
		if c.EmbeddingConfig == nil {
			return fmt.Errorf("%w: embedding_config required for semantic algorithm", ErrInvalidEmbeddingConfig)
		}
		if err := c.EmbeddingConfig.Validate(); err != nil {
			return err
		}
	} else if c.EmbeddingConfig != nil {
		return fmt.Errorf("%w: embedding_config is only valid for the semantic algorithm", ErrInvalidEmbeddingConfig)
	}
	if err := c.RegistryIDs.Validate(); err != nil {
		return err
	}
	if err := validateUniqueIDs(c.AuthIDs, ErrInvalidAuthID, "auth"); err != nil {
		return err
	}
	if err := c.Fallback.Validate(); err != nil {
		return err
	}
	if err := c.ModelPolicies.Validate(c.knownRegistryIDs()); err != nil {
		return err
	}
	if c.FailMode == "" {
		c.FailMode = FailModeClosed
	}
	if err := c.FailMode.Validate(); err != nil {
		return err
	}
	if len(c.Toolkit) > 0 {
		if c.Type != TypeMCP {
			return fmt.Errorf("%w: toolkit is only valid for MCP consumers", ErrInvalidToolkit)
		}
		if err := c.Toolkit.Validate(c.knownRegistryIDs()); err != nil {
			return err
		}
	}
	return nil
}

func (c *Consumer) knownRegistryIDs() map[ids.RegistryID]struct{} {
	known := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		known[id] = struct{}{}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
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
