package policy

import (
	"time"

	"github.com/google/uuid"
)

// Policy is the admin-managed aggregate that groups an ordered set of plugin
// executions for a Gateway. The runtime resolves a Policy by ID and applies
// its plugin chain to matching requests.
type Policy struct {
	ID        uuid.UUID `json:"id"`
	GatewayID uuid.UUID `json:"gateway_id"`
	Name      string    `json:"name"`
	Plugins   Plugins   `json:"plugins"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
