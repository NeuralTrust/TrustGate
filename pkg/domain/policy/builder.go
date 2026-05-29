package policy

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CreateParams struct {
	GatewayID uuid.UUID
	Name      string
	Plugins   Plugins
}

func New(params CreateParams) (*Policy, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("policy: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	plugins := params.Plugins
	if plugins == nil {
		plugins = make(Plugins, 0)
	}
	p := &Policy{
		ID:        id,
		GatewayID: params.GatewayID,
		Name:      params.Name,
		Plugins:   plugins,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}
