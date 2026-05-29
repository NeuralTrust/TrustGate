package policy

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Policy struct {
	ID        uuid.UUID `json:"id"`
	GatewayID uuid.UUID `json:"gateway_id"`
	Name      string    `json:"name"`
	Plugins   Plugins   `json:"plugins"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewPolicy(gatewayID uuid.UUID, name string, plugins Plugins) (*Policy, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("policy: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	if plugins == nil {
		plugins = make(Plugins, 0)
	}
	p := &Policy{
		ID:        id,
		GatewayID: gatewayID,
		Name:      name,
		Plugins:   plugins,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func Rehydrate(
	id, gatewayID uuid.UUID,
	name string,
	plugins Plugins,
	createdAt, updatedAt time.Time,
) *Policy {
	return &Policy{
		ID:        id,
		GatewayID: gatewayID,
		Name:      name,
		Plugins:   plugins,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

func (p *Policy) Validate() error {
	if p.Name == "" {
		return ErrInvalidName
	}
	if p.GatewayID == uuid.Nil {
		return ErrInvalidGatewayID
	}
	if p.Plugins == nil {
		p.Plugins = make(Plugins, 0)
	}
	return p.Plugins.Validate()
}
