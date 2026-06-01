package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/google/uuid"
)

type GatewayResponse struct {
	ID              uuid.UUID              `json:"id"`
	Name            string                 `json:"name"`
	Status          string                 `json:"status"`
	Telemetry       *telemetry.Telemetry   `json:"telemetry,omitempty"`
	ClientTLSConfig domain.ClientTLSConfig `json:"client_tls,omitempty"`
	SessionConfig   *domain.SessionConfig  `json:"session_config,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

func FromDomain(g *domain.Gateway) GatewayResponse {
	return GatewayResponse{
		ID:              g.ID,
		Name:            g.Name,
		Status:          g.Status,
		Telemetry:       g.Telemetry,
		ClientTLSConfig: g.ClientTLSConfig,
		SessionConfig:   g.SessionConfig,
		CreatedAt:       g.CreatedAt,
		UpdatedAt:       g.UpdatedAt,
	}
}
