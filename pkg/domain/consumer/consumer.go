package consumer

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
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
	ID              ids.ConsumerID           `json:"id"`
	GatewayID       ids.GatewayID            `json:"gateway_id"`
	Name            string                   `json:"name"`
	Type            Type                     `json:"type"`
	Path            string                   `json:"path"`
	Algorithm       string                   `json:"algorithm"`
	EmbeddingConfig *backend.EmbeddingConfig `json:"embedding_config,omitempty"`
	Headers         map[string]string        `json:"headers,omitempty"`
	Active          bool                     `json:"active"`
	BackendIDs      backend.Backends         `json:"backend_ids"`
	PolicyIDs       []ids.PolicyID           `json:"policy_ids"`
	AuthIDs         []ids.AuthID             `json:"auth_ids"`
	Fallback        *Fallback                `json:"fallback,omitempty"`
	ModelPolicies   ModelPolicies            `json:"model_policies,omitempty"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
}

type CreateParams struct {
	GatewayID       ids.GatewayID
	Name            string
	Type            Type
	Path            string
	Algorithm       string
	EmbeddingConfig *backend.EmbeddingConfig
	Headers         map[string]string
	Active          *bool
	BackendIDs      []ids.BackendID
	PolicyIDs       []ids.PolicyID
	AuthIDs         []ids.AuthID
	Fallback        *Fallback
	ModelPolicies   ModelPolicies
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
		BackendIDs:      params.BackendIDs,
		PolicyIDs:       params.PolicyIDs,
		AuthIDs:         params.AuthIDs,
		Fallback:        params.Fallback,
		ModelPolicies:   params.ModelPolicies,
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
	embeddingConfig *backend.EmbeddingConfig,
	headers map[string]string,
	active bool,
	backendIDs []ids.BackendID,
	policyIDs []ids.PolicyID,
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
		BackendIDs:      backendIDs,
		PolicyIDs:       policyIDs,
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
	}
	if len(c.BackendIDs) == 0 {
		return ErrNoBackends
	}
	if err := c.BackendIDs.Validate(); err != nil {
		return err
	}
	if err := validateUniqueIDs(c.PolicyIDs, ErrInvalidPolicyID, "policy"); err != nil {
		return err
	}
	if err := validateUniqueIDs(c.AuthIDs, ErrInvalidAuthID, "auth"); err != nil {
		return err
	}
	if err := c.Fallback.Validate(); err != nil {
		return err
	}
	if err := c.ModelPolicies.Validate(c.knownBackendIDs()); err != nil {
		return err
	}
	return nil
}

func (c *Consumer) knownBackendIDs() map[ids.BackendID]struct{} {
	known := make(map[ids.BackendID]struct{}, len(c.BackendIDs))
	for _, id := range c.BackendIDs {
		known[id] = struct{}{}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
			known[id] = struct{}{}
		}
	}
	return known
}

// identifier constrains the strongly typed domain IDs that share comparison,
// nil-detection and string rendering. It lets the slice helpers below stay
// generic across PolicyID, AuthID, etc.
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

func (c *Consumer) AttachBackend(id ids.BackendID) bool {
	out, ok := c.BackendIDs.Attach(id)
	c.BackendIDs = out
	return ok
}

func (c *Consumer) DetachBackend(id ids.BackendID) bool {
	out, ok := c.BackendIDs.Detach(id)
	c.BackendIDs = out
	return ok
}

func (c *Consumer) AttachPolicy(id ids.PolicyID) bool {
	out, ok := attachID(c.PolicyIDs, id)
	c.PolicyIDs = out
	return ok
}

func (c *Consumer) DetachPolicy(id ids.PolicyID) bool {
	out, ok := detachID(c.PolicyIDs, id)
	c.PolicyIDs = out
	return ok
}

func (c *Consumer) AttachAuth(id ids.AuthID) bool {
	out, ok := attachID(c.AuthIDs, id)
	c.AuthIDs = out
	return ok
}

func (c *Consumer) DetachAuth(id ids.AuthID) bool {
	out, ok := detachID(c.AuthIDs, id)
	c.AuthIDs = out
	return ok
}

func attachID[T identifier](list []T, id T) ([]T, bool) {
	if id.IsNil() {
		return list, false
	}
	for _, existing := range list {
		if existing == id {
			return list, false
		}
	}
	return append(list, id), true
}

func detachID[T identifier](list []T, id T) ([]T, bool) {
	for i, existing := range list {
		if existing == id {
			return append(list[:i], list[i+1:]...), true
		}
	}
	return list, false
}
