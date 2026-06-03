package registry

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

type Registry struct {
	ID              ids.RegistryID `json:"id"`
	GatewayID       ids.GatewayID  `json:"gateway_id"`
	Name            string         `json:"name"`
	Provider        string         `json:"provider"`
	ProviderOptions map[string]any `json:"provider_options,omitempty"`
	Description     string         `json:"description,omitempty"`
	Weight          int            `json:"weight,omitempty"`
	Auth            *TargetAuth    `json:"auth,omitempty"`
	HealthChecks    *HealthChecks  `json:"health_checks,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func NewRegistry(
	gatewayID ids.GatewayID,
	name, provider string,
	providerOptions map[string]any,
	description string,
	weight int,
	auth *TargetAuth,
	healthChecks *HealthChecks,
) (*Registry, error) {
	id, err := ids.NewV7[ids.RegistryKind]()
	if err != nil {
		return nil, fmt.Errorf("registry: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	b := &Registry{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            name,
		Provider:        provider,
		ProviderOptions: providerOptions,
		Description:     description,
		Weight:          weight,
		Auth:            auth,
		HealthChecks:    healthChecks,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func Rehydrate(
	id ids.RegistryID,
	gatewayID ids.GatewayID,
	name, provider string,
	providerOptions map[string]any,
	description string,
	weight int,
	auth *TargetAuth,
	healthChecks *HealthChecks,
	createdAt, updatedAt time.Time,
) *Registry {
	return &Registry{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            name,
		Provider:        provider,
		ProviderOptions: providerOptions,
		Description:     description,
		Weight:          weight,
		Auth:            auth,
		HealthChecks:    healthChecks,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

func (b *Registry) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidRegistry)
	}
	if b.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	if b.Weight < 0 {
		return fmt.Errorf("%w: weight cannot be negative", ErrInvalidRegistry)
	}
	if b.Provider == "" {
		return fmt.Errorf("%w: provider is required", ErrInvalidRegistry)
	}
	if !providers.IsValidProvider(b.Provider) {
		return fmt.Errorf("%w: unsupported provider %q", ErrInvalidRegistry, b.Provider)
	}
	if b.Auth == nil {
		return fmt.Errorf("%w: auth is required", ErrInvalidRegistry)
	}
	if err := b.Auth.Validate(); err != nil {
		return err
	}
	if b.HealthChecks != nil {
		if err := b.HealthChecks.Validate(); err != nil {
			return err
		}
	}
	return nil
}
