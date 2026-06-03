package response

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type PolicyResponse struct {
	ID        ids.PolicyID     `json:"id"`
	GatewayID ids.GatewayID    `json:"gateway_id"`
	Name      string           `json:"name"`
	Plugins   []PluginResponse `json:"plugins"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

type PluginResponse struct {
	ID       string                 `json:"id,omitempty"`
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Stage    string                 `json:"stage"`
	Priority int                    `json:"priority"`
	Parallel bool                   `json:"parallel,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

func FromPolicy(p *domain.Policy) PolicyResponse {
	plugins := make([]PluginResponse, 0, len(p.Plugins))
	for _, pl := range p.Plugins {
		plugins = append(plugins, fromPlugin(pl))
	}
	return PolicyResponse{
		ID:        p.ID,
		GatewayID: p.GatewayID,
		Name:      p.Name,
		Plugins:   plugins,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func fromPlugin(p domain.Plugin) PluginResponse {
	return PluginResponse{
		ID:       p.ID,
		Name:     p.Name,
		Enabled:  p.Enabled,
		Stage:    string(p.Stage),
		Priority: p.Priority,
		Parallel: p.Parallel,
		Settings: p.Settings,
	}
}
