package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

type GatewayResponse struct {
	ID              ids.GatewayID          `json:"id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Status          string                 `json:"status"`
	Domain          string                 `json:"domain,omitempty"`
	Telemetry       *telemetry.Telemetry   `json:"telemetry,omitempty"`
	ClientTLSConfig domain.ClientTLSConfig `json:"client_tls,omitempty"`
	SessionConfig   *domain.SessionConfig  `json:"session_config,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

func FromDomain(g *domain.Gateway) GatewayResponse {
	if g == nil {
		return GatewayResponse{}
	}
	return GatewayResponse{
		ID:              g.ID,
		Name:            g.Name,
		Slug:            g.Slug,
		Status:          g.Status,
		Domain:          g.Domain,
		Telemetry:       g.Telemetry,
		ClientTLSConfig: g.ClientTLSConfig,
		SessionConfig:   g.SessionConfig,
		CreatedAt:       g.CreatedAt,
		UpdatedAt:       g.UpdatedAt,
	}
}
