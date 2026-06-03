package policy

import (
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Policy struct {
	ID        ids.PolicyID   `json:"id"`
	GatewayID ids.GatewayID  `json:"gateway_id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	Enabled   bool           `json:"enabled"`
	Priority  int            `json:"priority"`
	Parallel  bool           `json:"parallel"`
	Settings  map[string]any `json:"settings,omitempty"`
	Stages    []Stage        `json:"stages,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func NewPolicy(
	gatewayID ids.GatewayID,
	name string,
	slug string,
	enabled bool,
	priority int,
	parallel bool,
	settings map[string]any,
	stages []Stage,
) (*Policy, error) {
	id, err := ids.NewV7[ids.PolicyKind]()
	if err != nil {
		return nil, fmt.Errorf("policy: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	p := &Policy{
		ID:        id,
		GatewayID: gatewayID,
		Name:      name,
		Slug:      slug,
		Enabled:   enabled,
		Priority:  priority,
		Parallel:  parallel,
		Settings:  settings,
		Stages:    stages,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func Rehydrate(
	id ids.PolicyID,
	gatewayID ids.GatewayID,
	name string,
	slug string,
	enabled bool,
	priority int,
	parallel bool,
	settings map[string]any,
	stages []Stage,
	createdAt, updatedAt time.Time,
) *Policy {
	return &Policy{
		ID:        id,
		GatewayID: gatewayID,
		Name:      name,
		Slug:      slug,
		Enabled:   enabled,
		Priority:  priority,
		Parallel:  parallel,
		Settings:  settings,
		Stages:    stages,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

func (p *Policy) Validate() error {
	if p.Name == "" {
		return ErrInvalidName
	}
	if p.Slug == "" {
		return ErrInvalidSlug
	}
	if p.GatewayID.IsNil() {
		return ErrInvalidGatewayID
	}
	for _, s := range p.Stages {
		if !s.IsValid() {
			return fmt.Errorf("%w: %q", ErrInvalidStage, s)
		}
	}
	return nil
}
