package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

type ConsumerResponse struct {
	ID         uuid.UUID         `json:"id"`
	GatewayID  uuid.UUID         `json:"gateway_id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Headers    map[string]string `json:"headers,omitempty"`
	Active     bool              `json:"active"`
	BackendIDs []uuid.UUID       `json:"backend_ids"`
	PolicyIDs  []uuid.UUID       `json:"policy_ids"`
	AuthIDs    []uuid.UUID       `json:"auth_ids"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

func FromConsumer(c *domain.Consumer) ConsumerResponse {
	if c == nil {
		return ConsumerResponse{}
	}
	backendIDs := c.BackendIDs
	if backendIDs == nil {
		backendIDs = []uuid.UUID{}
	}
	policyIDs := c.PolicyIDs
	if policyIDs == nil {
		policyIDs = []uuid.UUID{}
	}
	authIDs := c.AuthIDs
	if authIDs == nil {
		authIDs = []uuid.UUID{}
	}
	return ConsumerResponse{
		ID:         c.ID,
		GatewayID:  c.GatewayID,
		Name:       c.Name,
		Type:       string(c.Type),
		Headers:    c.Headers,
		Active:     c.Active,
		BackendIDs: backendIDs,
		PolicyIDs:  policyIDs,
		AuthIDs:    authIDs,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}
