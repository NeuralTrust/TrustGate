package gateway

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/google/uuid"
)

type Gateway struct {
	ID              uuid.UUID            `json:"id"`
	Name            string               `json:"name"`
	Status          string               `json:"status"`
	Telemetry       *telemetry.Telemetry `json:"telemetry,omitempty"`
	ClientTLSConfig ClientTLSConfig      `json:"client_tls,omitempty"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

func New(name string) (*Gateway, error) {
	now := time.Now().UTC()
	g := &Gateway{
		ID:        uuid.New(),
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return g, nil
}

func Rehydrate(
	id uuid.UUID,
	name, status string,
	tel *telemetry.Telemetry,
	clientTLS ClientTLSConfig,
	createdAt, updatedAt time.Time,
) *Gateway {
	return &Gateway{
		ID:              id,
		Name:            name,
		Status:          status,
		Telemetry:       tel,
		ClientTLSConfig: clientTLS,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
}

type ClientTLSConfig map[string]json.RawMessage

func (c ClientTLSConfig) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}

func (c *ClientTLSConfig) Scan(value interface{}) error {
	if value == nil {
		*c = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, c)
}

func (g *Gateway) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("name is required")
	}

	if g.Status == "" {
		g.Status = "active"
	}

	return nil
}
