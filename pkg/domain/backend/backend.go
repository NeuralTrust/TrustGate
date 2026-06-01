package backend

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Backend is a single load-balancing target: one provider endpoint with its
// credentials and optional weight/description/health-check config. A Consumer
// owns a pool of backends and the algorithm used to balance across them.
type Backend struct {
	ID              uuid.UUID      `json:"id"`
	GatewayID       uuid.UUID      `json:"gateway_id"`
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

func NewBackend(
	gatewayID uuid.UUID,
	name, provider string,
	providerOptions map[string]any,
	description string,
	weight int,
	auth *TargetAuth,
	healthChecks *HealthChecks,
) (*Backend, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("backend: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	b := &Backend{
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
	id, gatewayID uuid.UUID,
	name, provider string,
	providerOptions map[string]any,
	description string,
	weight int,
	auth *TargetAuth,
	healthChecks *HealthChecks,
	createdAt, updatedAt time.Time,
) *Backend {
	return &Backend{
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

func (b *Backend) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidBackend)
	}
	if b.GatewayID == uuid.Nil {
		return ErrInvalidGatewayID
	}
	if b.Weight < 0 {
		return fmt.Errorf("%w: weight cannot be negative", ErrInvalidBackend)
	}
	if b.Provider == "" {
		return fmt.Errorf("%w: provider is required", ErrInvalidBackend)
	}
	if b.Auth == nil {
		return fmt.Errorf("%w: auth is required", ErrInvalidBackend)
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
