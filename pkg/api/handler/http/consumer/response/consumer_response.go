package response

import (
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/google/uuid"
)

type ConsumerResponse struct {
	ID            uuid.UUID         `json:"id"`
	GatewayID     uuid.UUID         `json:"gateway_id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Path          string            `json:"path"`
	Paths         []string          `json:"paths,omitempty"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     bool              `json:"strip_path"`
	PreserveHost  bool              `json:"preserve_host"`
	Active        bool              `json:"active"`
	Public        bool              `json:"public"`
	RetryAttempts int               `json:"retry_attempts"`
	BackendIDs    []uuid.UUID       `json:"backend_ids"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

func FromConsumer(c *domain.Consumer) ConsumerResponse {
	if c == nil {
		return ConsumerResponse{}
	}
	backendIDs := c.BackendIDs
	if backendIDs == nil {
		backendIDs = []uuid.UUID{}
	}
	methods := c.Methods
	if methods == nil {
		methods = []string{}
	}
	return ConsumerResponse{
		ID:            c.ID,
		GatewayID:     c.GatewayID,
		Name:          c.Name,
		Type:          string(c.Type),
		Path:          c.Path,
		Paths:         c.Paths,
		Methods:       methods,
		Headers:       c.Headers,
		StripPath:     c.StripPath,
		PreserveHost:  c.PreserveHost,
		Active:        c.Active,
		Public:        c.Public,
		RetryAttempts: c.RetryAttempts,
		BackendIDs:    backendIDs,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}
