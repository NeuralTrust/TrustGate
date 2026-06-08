package response

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type PolicyResponse struct {
	ID          ids.PolicyID     `json:"id"`
	GatewayID   ids.GatewayID    `json:"gateway_id"`
	ConsumerIDs []ids.ConsumerID `json:"consumer_ids,omitempty"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Slug        string           `json:"slug"`
	Enabled     bool             `json:"enabled"`
	Global      bool             `json:"global"`
	Priority    int              `json:"priority"`
	Parallel    bool             `json:"parallel,omitempty"`
	Settings    map[string]any   `json:"settings,omitempty"`
	Stages      []string         `json:"stages,omitempty"`
	Mode        string           `json:"mode"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

func FromPolicy(p *domain.Policy) PolicyResponse {
	return PolicyResponse{
		ID:          p.ID,
		GatewayID:   p.GatewayID,
		ConsumerIDs: p.ConsumerIDs,
		Name:        p.Name,
		Description: p.Description,
		Slug:        p.Slug,
		Enabled:     p.Enabled,
		Global:      p.Global,
		Priority:    p.Priority,
		Parallel:    p.Parallel,
		Settings:    p.Settings,
		Stages:      fromStages(p.Stages),
		Mode:        string(p.Mode.Normalize()),
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

func fromStages(stages []domain.Stage) []string {
	if len(stages) == 0 {
		return nil
	}
	out := make([]string, 0, len(stages))
	for _, s := range stages {
		out = append(out, string(s))
	}
	return out
}
