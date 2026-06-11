package consumer

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
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

type RoutingMode string

const (
	RoutingModeInline    RoutingMode = "inline"
	RoutingModeRoleBased RoutingMode = "role_based"
)

func (m RoutingMode) IsValid() bool {
	switch m {
	case RoutingModeInline, RoutingModeRoleBased:
		return true
	}
	return false
}

type Consumer struct {
	ID            ids.ConsumerID    `json:"id"`
	GatewayID     ids.GatewayID     `json:"gateway_id"`
	Name          string            `json:"name"`
	Type          Type              `json:"type"`
	Slug          string            `json:"slug"`
	RoutingMode   RoutingMode       `json:"routing_mode"`
	LBConfig      *LBConfig         `json:"lb_config,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Active        bool              `json:"active"`
	RegistryIDs   []ids.RegistryID  `json:"registry_ids"`
	RoleIDs       []ids.RoleID      `json:"role_ids"`
	AuthIDs       []ids.AuthID      `json:"auth_ids"`
	Fallback      *Fallback         `json:"fallback,omitempty"`
	ModelPolicies ModelPolicies     `json:"model_policies,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type CreateParams struct {
	GatewayID     ids.GatewayID
	Name          string
	Type          Type
	RoutingMode   RoutingMode
	LBConfig      *LBConfig
	Headers       map[string]string
	Active        *bool
	RegistryIDs   []ids.RegistryID
	RoleIDs       []ids.RoleID
	AuthIDs       []ids.AuthID
	Fallback      *Fallback
	ModelPolicies ModelPolicies
}

func New(params CreateParams) (*Consumer, error) {
	id, err := ids.NewV7[ids.ConsumerKind]()
	if err != nil {
		return nil, fmt.Errorf("consumer: generate uuid: %w", err)
	}
	slug, err := NewSlug()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	active := true
	if params.Active != nil {
		active = *params.Active
	}
	c := &Consumer{
		ID:            id,
		GatewayID:     params.GatewayID,
		Name:          params.Name,
		Type:          params.Type,
		Slug:          slug,
		RoutingMode:   params.RoutingMode,
		LBConfig:      params.LBConfig,
		Headers:       params.Headers,
		Active:        active,
		RegistryIDs:   params.RegistryIDs,
		RoleIDs:       params.RoleIDs,
		AuthIDs:       params.AuthIDs,
		Fallback:      params.Fallback,
		ModelPolicies: params.ModelPolicies,
		CreatedAt:     now,
		UpdatedAt:     now,
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
	slug string,
	routingMode RoutingMode,
	lbConfig *LBConfig,
	headers map[string]string,
	active bool,
	registryIDs []ids.RegistryID,
	roleIDs []ids.RoleID,
	authIDs []ids.AuthID,
	fallback *Fallback,
	modelPolicies ModelPolicies,
	createdAt, updatedAt time.Time,
) *Consumer {
	return &Consumer{
		ID:            id,
		GatewayID:     gatewayID,
		Name:          name,
		Type:          consumerType,
		Slug:          slug,
		RoutingMode:   routingMode,
		LBConfig:      lbConfig,
		Headers:       headers,
		Active:        active,
		RegistryIDs:   registryIDs,
		RoleIDs:       roleIDs,
		AuthIDs:       authIDs,
		Fallback:      fallback,
		ModelPolicies: modelPolicies,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
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
	if !IsValidSlug(c.Slug) {
		return fmt.Errorf("%w: %q", ErrInvalidSlug, c.Slug)
	}
	if c.RoutingMode == "" {
		c.RoutingMode = RoutingModeInline
	}
	if !c.RoutingMode.IsValid() {
		return fmt.Errorf("%w: %q", ErrInvalidRoutingMode, c.RoutingMode)
	}
	if err := validateUniqueIDs(c.AuthIDs, ErrInvalidAuthID, "auth"); err != nil {
		return err
	}
	if c.RoutingMode == RoutingModeRoleBased {
		return c.validateRoleBased()
	}
	if err := validateUniqueIDs(c.RegistryIDs, ErrInvalidModelPolicy, "registry"); err != nil {
		return err
	}
	if err := c.Fallback.Validate(); err != nil {
		return err
	}
	if err := c.ModelPolicies.Validate(c.knownRegistryIDs()); err != nil {
		return err
	}
	if err := c.LBConfig.Validate(c.ModelPolicies); err != nil {
		return err
	}
	return validateUniqueIDs(c.RoleIDs, ErrInvalidRoutingMode, "role")
}

func (c *Consumer) validateRoleBased() error {
	if len(c.RegistryIDs) > 0 {
		return fmt.Errorf("%w: registry_ids are only valid in inline mode", ErrInvalidRoutingMode)
	}
	if c.LBConfig != nil {
		return fmt.Errorf("%w: lb_config is only valid in inline mode", ErrInvalidRoutingMode)
	}
	if c.Fallback != nil && c.Fallback.Enabled {
		return fmt.Errorf("%w: fallback is only valid in inline mode", ErrInvalidRoutingMode)
	}
	if len(c.ModelPolicies) > 0 {
		return fmt.Errorf("%w: model_policies are only valid in inline mode", ErrInvalidRoutingMode)
	}
	if err := validateUniqueIDs(c.RoleIDs, ErrInvalidRoutingMode, "role"); err != nil {
		return err
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
